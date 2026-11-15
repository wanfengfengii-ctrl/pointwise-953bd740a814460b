"""Offline correction package decoder and store (CHG1 finite format).

Implements the contract in CONTRACT.md using only the Python standard
library.  Two public pieces:

* ``Decoder(chunks)``: a single-shot, chunk-by-chunk streaming parser of the
  finite CHG1 wire format.  It never buffers a whole package or a whole
  value: payloads leave the decoder as bounded ``data`` events of at most
  65536 bytes each.
* ``Store(path)``: an SQLite backed warehouse that consumes operation event
  streams (from ``Decoder`` or any third-party source), independently
  re-validates every event, stages everything outside the main table and
  applies the whole batch in one transaction against the pre-batch image.
"""

import codecs
import hashlib
import sqlite3

# ---------------------------------------------------------------------------
# Wire format constants
# ---------------------------------------------------------------------------

MAGIC = b"CHG1"
MAX_CHUNK = 65536
MAX_UVAR = (1 << 63) - 1
INT64_MIN = -(1 << 63)
INT64_MAX = (1 << 63) - 1

OP_INSERT = 0x12
OP_DELETE = 0x09
OP_UPDATE = 0x17
END_MARKER = 0x00
_OP_NAMES = {
    OP_INSERT: "insert",
    OP_DELETE: "delete",
    OP_UPDATE: "update",
}

_MARKER_UNSET = 0
_MARKER_INT = 1
_MARKER_TEXT = 3
_MARKER_BLOB = 4
_MARKER_NULL = 5
_MARKER_KINDS = {
    _MARKER_UNSET: "unset",
    _MARKER_INT: "int",
    _MARKER_TEXT: "text",
    _MARKER_BLOB: "blob",
    _MARKER_NULL: "null",
}

COLUMNS = ("id", "tag", "payload")
_FIELD_PAIRS = {
    "insert": [("new", c) for c in COLUMNS],
    "delete": [("old", c) for c in COLUMNS],
    "update": [("old", c) for c in COLUMNS]
    + [("new", c) for c in COLUMNS],
}
_ALLOWED_KINDS = {
    "id": frozenset(("unset", "int")),
    "tag": frozenset(("unset", "null", "text")),
    "payload": frozenset(("unset", "null", "blob")),
}
_COUNT_COLUMN = {
    "insert": "inserted",
    "update": "updated",
    "delete": "deleted",
}


# ---------------------------------------------------------------------------
# Decoder
# ---------------------------------------------------------------------------


class Decoder:
    """Single-shot iterable parser over a stream of fixed-size byte chunks.

    ``chunks`` is an iterable of ``bytes`` objects, each 0..65536 bytes
    long.  Iterating yields plain dict events as described in CONTRACT.md.
    Any format violation raises ``ValueError``; exceptions raised by the
    chunk source itself propagate unchanged.
    """

    def __init__(self, chunks):
        self._chunks = iter(chunks)
        self._buf = b""
        self._pos = 0
        self._exhausted = False
        self._events = self._parse()

    def __iter__(self):
        return self

    def __next__(self):
        return next(self._events)

    # -- low level byte feeding -------------------------------------------

    def _pull(self):
        """Load the next chunk. Returns False at clean end of stream."""
        if self._exhausted:
            return False
        try:
            chunk = next(self._chunks)
        except StopIteration:
            self._exhausted = True
            return False
        if not isinstance(chunk, bytes) or len(chunk) > MAX_CHUNK:
            raise ValueError(
                "chunks must be bytes of 0..%d bytes" % MAX_CHUNK
            )
        # Retain only the unconsumed tail; a consumed chunk is never held.
        self._buf = self._buf[self._pos:]
        self._pos = 0
        if chunk:
            self._buf += chunk
        return True

    def _need_byte(self):
        while self._pos >= len(self._buf):
            if not self._pull():
                raise ValueError("unexpected end of package")
        b = self._buf[self._pos]
        self._pos += 1
        return b

    def _read_n(self, n):
        while len(self._buf) - self._pos < n:
            if not self._pull():
                raise ValueError("unexpected end of package")
        data = self._buf[self._pos:self._pos + n]
        self._pos += n
        return data

    def _read_uvar(self):
        """Shortest unsigned LEB128, at most 9 bytes, value <= 2**63-1.

        Nine bytes carry 9*7 = 63 payload bits: the first eight bytes hold
        the low 56 bits; the ninth byte holds value bits 56..62 and must
        not itself carry a continuation bit.
        """
        result = 0
        for i in range(9):
            b = self._need_byte()
            if i < 8:
                result |= (b & 0x7F) << (7 * i)
                if not (b & 0x80):
                    if i > 0 and b == 0:
                        raise ValueError("non-shortest uvar encoding")
                    return result
                continue
            # Ninth byte: a continuation would imply a forbidden 10th byte;
            # its seven payload bits land at value bits 56..62, so any
            # 0x01..0x7F stays within 2**63-1. Zero would be non-shortest.
            if b & 0x80:
                raise ValueError("uvar exceeds 9 bytes")
            if b == 0:
                raise ValueError("non-shortest uvar encoding")
            return result | (b << 56)
        raise ValueError("uvar too long")

    # -- parsing -----------------------------------------------------------

    def _parse(self):
        header = self._read_n(len(MAGIC))
        if header != MAGIC:
            raise ValueError("bad package magic: %r" % (header,))

        seq = 0
        while True:
            opcode = self._need_byte()
            if opcode == END_MARKER:
                # Terminator consumed; the source must be at EOF now,
                # committing on the marker alone is not enough.
                self._require_eof()
                return
            name = _OP_NAMES.get(opcode)
            if name is None:
                raise ValueError("unknown opcode 0x%02x" % opcode)

            yield {"seq": seq, "op": name}
            kinds = {"old": {}, "new": {}}
            for side, column in _FIELD_PAIRS[name]:
                kind, value, length = self._read_field(column)
                field = {
                    "seq": seq,
                    "side": side,
                    "column": column,
                    "kind": kind,
                    "length": length,
                }
                if kind == "int":
                    field["value"] = value
                yield field

                if kind in ("text", "blob"):
                    remaining = length
                    decoder = (
                        codecs.getincrementaldecoder("utf-8")(
                            errors="strict"
                        )
                        if kind == "text"
                        else None
                    )
                    while remaining:
                        block = self._read_n(min(MAX_CHUNK, remaining))
                        remaining -= len(block)
                        if decoder is not None:
                            try:
                                decoder.decode(block)
                            except UnicodeError as exc:
                                raise ValueError(
                                    "invalid UTF-8 text"
                                ) from exc
                        yield {"seq": seq, "data": block}
                    if decoder is not None:
                        try:
                            decoder.decode(b"", final=True)
                        except UnicodeError as exc:
                            raise ValueError("invalid UTF-8 text") from exc
                yield {"seq": seq}  # field_end
                kinds[side][column] = kind

            _check_row(name, kinds)
            yield {"seq": seq}  # end
            seq += 1

    def _require_eof(self):
        if self._pos < len(self._buf):
            raise ValueError("trailing bytes after end marker")
        while self._pull():
            if self._buf:
                raise ValueError("trailing bytes after end marker")

    def _read_field(self, column):
        """Parse one field marker and its value header."""
        marker = self._need_byte()
        kind = _MARKER_KINDS.get(marker)
        if kind is None:
            raise ValueError("unknown field marker %d" % marker)
        if kind not in _ALLOWED_KINDS[column]:
            raise ValueError(
                "field %s cannot use kind %s" % (column, kind)
            )
        if kind == "unset":
            return "unset", None, 0
        if kind == "null":
            return "null", None, 0
        if kind == "int":
            value = int.from_bytes(self._read_n(8), "big", signed=True)
            return "int", value, 0
        length = self._read_uvar()  # text / blob body length
        return kind, None, length


def _check_row(name, kinds):
    """Per-row structural/semantic rules owned by the decoder."""
    if name == "insert":
        if any(k == "unset" for k in kinds["new"].values()):
            raise ValueError("insert row must provide every field")
        return
    if name == "delete":
        if kinds["old"]["id"] != "int":
            raise ValueError("delete requires an old id")
        return
    # update
    if kinds["old"]["id"] != "int":
        raise ValueError("update requires an old id")
    if kinds["new"]["id"] not in ("unset", "int"):
        raise ValueError("new id must be unset or an integer")
    for column in ("tag", "payload"):
        if (kinds["new"][column] != "unset"
                and kinds["old"][column] == "unset"):
            raise ValueError(
                "new %s provided without matching old field" % column
            )


# ---------------------------------------------------------------------------
# Store
# ---------------------------------------------------------------------------


class Store:
    """SQLite warehouse for the single ``items`` table.

    Batch data always lands in private staging tables first; the production
    ``items`` / ``items_meta`` tables are touched only inside the final
    transaction, so a rejected batch or a killed process leaves the
    pre-batch database intact.
    """

    _BEGIN_KEYS = frozenset(("seq", "op"))
    _FIELD_KEYS = frozenset(
        ("seq", "side", "column", "kind", "length")
    )
    _DATA_KEYS = frozenset(("seq", "data"))
    _SEQ_KEYS = frozenset(("seq",))

    def __init__(self, path):
        self._path = str(path)
        self._closed = False
        self._conn = sqlite3.connect(self._path)
        self._ensure_schema()
        # Clear staging leftovers from a process killed mid-apply.  Only
        # this store's own private tables are touched; no files are removed.
        self._conn.execute("DELETE FROM stg_op")
        self._conn.execute("DELETE FROM stg_field")
        self._conn.execute("DELETE FROM stg_chunk")
        self._conn.execute("DELETE FROM stg_final")
        self._conn.commit()

    # -- lifecycle ---------------------------------------------------------

    def close(self):
        if not self._closed:
            self._closed = True
            self._conn.close()

    def __enter__(self):
        return self

    def __exit__(self, exc_type, exc, tb):
        self.close()

    def _check_open(self):
        if self._closed:
            raise ValueError("store is closed")

    def _ensure_schema(self):
        c = self._conn
        c.execute(
            "CREATE TABLE IF NOT EXISTS items ("
            "id INTEGER PRIMARY KEY, tag TEXT, payload BLOB)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS items_meta ("
            "id INTEGER PRIMARY KEY, "
            "tag_sha256 BLOB, payload_sha256 BLOB)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS stg_op ("
            "seq INTEGER PRIMARY KEY, op TEXT NOT NULL)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS stg_field ("
            "seq INTEGER NOT NULL, side TEXT NOT NULL, column TEXT NOT NULL,"
            " kind TEXT NOT NULL, val_int INTEGER, val_blob BLOB,"
            " length INTEGER NOT NULL, hash BLOB,"
            " PRIMARY KEY (seq, side, column))"
        )
        # Value bodies are kept as ordered <=64 KiB chunk rows instead of
        # one big BLOB: large payloads never materialise in Python memory
        # and are rebuilt inside SQLite by a linear recursive CTE.
        c.execute(
            "CREATE TABLE IF NOT EXISTS stg_chunk ("
            "seq INTEGER NOT NULL, side TEXT NOT NULL, column TEXT NOT NULL,"
            " idx INTEGER NOT NULL, piece BLOB NOT NULL)"
        )
        c.execute(
            "CREATE INDEX IF NOT EXISTS stg_chunk_idx ON stg_chunk "
            "(seq, side, column, idx)"
        )
        c.execute(
            "CREATE TABLE IF NOT EXISTS stg_final ("
            "id INTEGER PRIMARY KEY, tag BLOB, payload BLOB,"
            " tag_sha256 BLOB, payload_sha256 BLOB)"
        )
        c.commit()

    # -- small-scale helpers ----------------------------------------------

    def seed(self, rows):
        """Initialise an empty database atomically with ``rows``."""
        self._check_open()
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            if conn.execute("SELECT COUNT(*) FROM items").fetchone()[0]:
                raise ValueError("seed() is only valid on an empty store")
            for row in rows:
                if not isinstance(row, tuple) or len(row) != 3:
                    raise ValueError("seed rows must be (id, tag, payload)")
                rid, tag, payload = row
                self._validate_value_row(rid, tag, payload)
                tag_blob = None if tag is None else tag.encode("utf-8")
                tag_hash = (
                    None if tag is None
                    else hashlib.sha256(tag_blob).digest()
                )
                payload_hash = (
                    None if payload is None
                    else hashlib.sha256(payload).digest()
                )
                conn.execute(
                    "INSERT INTO items (id, tag, payload) VALUES (?,?,?)",
                    (rid, tag_blob, payload),
                )
                conn.execute(
                    "INSERT INTO items_meta "
                    "(id, tag_sha256, payload_sha256) VALUES (?,?,?)",
                    (rid, tag_hash, payload_hash),
                )
            conn.commit()
        except BaseException:
            conn.rollback()
            raise

    @staticmethod
    def _validate_value_row(rid, tag, payload):
        if isinstance(rid, bool) or not isinstance(rid, int):
            raise ValueError("id must be a non-boolean integer")
        if not INT64_MIN <= rid <= INT64_MAX:
            raise ValueError("id out of signed 64-bit range")
        if tag is not None and not isinstance(tag, str):
            raise ValueError("tag must be str or None")
        if payload is not None and not isinstance(
            payload, (bytes, bytearray)
        ):
            raise ValueError("payload must be bytes or None")

    def read(self, rid):
        """Return (id, tag, payload) for small-scale verification."""
        self._check_open()
        if isinstance(rid, bool) or not isinstance(rid, int):
            raise ValueError("id must be a non-boolean integer")
        # CAST forces TEXT affinity back to a Python str even when the row
        # originated from BLOB staging (content is validated UTF-8).
        cur = self._conn.execute(
            "SELECT id, CAST(tag AS TEXT), payload FROM items WHERE id=?",
            (rid,),
        )
        return cur.fetchone()

    def summary(self):
        """[(id, tag, payload_size_or_None, payload_sha256_or_None)] by id."""
        self._check_open()
        out = []
        cur = self._conn.execute(
            "SELECT i.id, CAST(i.tag AS TEXT), "
            "CASE WHEN i.payload IS NULL THEN NULL "
            "ELSE length(i.payload) END, m.payload_sha256 "
            "FROM items i LEFT JOIN items_meta m ON m.id = i.id "
            "ORDER BY i.id"
        )
        for rid, tag, size, digest in cur:
            out.append((rid, tag, size, digest))
        return out

    # -- apply -------------------------------------------------------------

    def apply(self, operations):
        """Apply one complete correction batch.

        ``operations`` is any iterable of contract events (a ``Decoder`` or
        a third-party source).  Validation is independent of the decoder's
        private state.  Either the whole batch commits or the pre-batch
        database is untouched; source exceptions propagate unchanged,
        rejections raise ``ValueError``.
        """
        self._check_open()
        conn = self._conn
        try:
            conn.execute("BEGIN IMMEDIATE")
            conn.execute("DELETE FROM stg_op")
            conn.execute("DELETE FROM stg_field")
            conn.execute("DELETE FROM stg_chunk")
            conn.execute("DELETE FROM stg_final")

            self._ingest(conn, operations)
            counts = self._validate_and_commit(conn)
            conn.commit()
            return counts
        except BaseException:
            conn.rollback()
            # Keep private staging tidy; main tables were never modified.
            try:
                conn.execute("DELETE FROM stg_op")
                conn.execute("DELETE FROM stg_field")
                conn.execute("DELETE FROM stg_chunk")
                conn.execute("DELETE FROM stg_final")
                conn.commit()
            except sqlite3.Error:
                pass
            raise

    # -- event ingestion (independent validation) -------------------------

    def _ingest(self, conn, operations):
        state = "between"        # between | field | fieldbody | end
        cur_seq = None
        cur_op = None
        pairs = None
        pair_idx = 0
        cur_side = cur_column = cur_kind = None
        cur_len = got_len = chunk_idx = 0
        text_decoder = None
        hasher = None
        next_seq = 0
        old_kinds = {}

        for event in operations:
            if not isinstance(event, dict):
                raise ValueError("event must be a dict")
            keys = frozenset(event)

            if keys == self._BEGIN_KEYS:
                if state != "between":
                    raise ValueError("nested or misplaced begin event")
                seq, op = event["seq"], event["op"]
                if (not isinstance(seq, int) or isinstance(seq, bool)
                        or seq != next_seq):
                    raise ValueError("seq must be continuous from 0")
                if op not in _FIELD_PAIRS:
                    raise ValueError("unknown op %r" % (op,))
                conn.execute(
                    "INSERT INTO stg_op (seq, op) VALUES (?,?)", (seq, op)
                )
                cur_seq, cur_op = seq, op
                pairs = _FIELD_PAIRS[op]
                pair_idx = 0
                old_kinds = {}
                state = "field"
                next_seq += 1
                continue

            if keys in (self._FIELD_KEYS,
                        self._FIELD_KEYS | frozenset(("value",))):
                if state != "field":
                    raise ValueError("field event in wrong position")
                seq = event["seq"]
                side = event["side"]
                column = event["column"]
                kind = event["kind"]
                length = event["length"]
                if seq != cur_seq:
                    raise ValueError("field seq does not match begin")
                if (side, column) != pairs[pair_idx]:
                    raise ValueError(
                        "field order must be old row then new row, "
                        "id/tag/payload"
                    )
                if (not isinstance(length, int) or isinstance(length, bool)
                        or length < 0):
                    raise ValueError("length must be a non-negative int")
                if kind not in _ALLOWED_KINDS[column]:
                    raise ValueError(
                        "column %s cannot use kind %s" % (column, kind)
                    )
                if kind == "int":
                    if "value" not in event or length != 0:
                        raise ValueError("int field needs value, length 0")
                    value = event["value"]
                    if (isinstance(value, bool)
                            or not isinstance(value, int)):
                        raise ValueError(
                            "int value must be a non-bool integer"
                        )
                    if not INT64_MIN <= value <= INT64_MAX:
                        raise ValueError("int value out of signed 64 range")
                    if column != "id":
                        raise ValueError("only id may carry an int")
                    val_int = value
                else:
                    if "value" in event:
                        raise ValueError(
                            "non-int field must not carry value"
                        )
                    val_int = None
                    if kind in ("unset", "null") and length != 0:
                        raise ValueError("unset/null length must be 0")

                # Row-level semantic rules (mirror the decoder rules).
                if cur_op == "insert" and kind == "unset":
                    raise ValueError(
                        "insert row must provide every field"
                    )
                if side == "old" and column == "id" and kind != "int":
                    raise ValueError(
                        "%s requires an old id" % cur_op
                    )
                if cur_op == "update" and side == "new":
                    if column == "id" and kind not in ("unset", "int"):
                        raise ValueError(
                            "new id must be unset or an integer"
                        )
                    if (column in ("tag", "payload") and kind != "unset"
                            and old_kinds.get(column) == "unset"):
                        raise ValueError(
                            "new %s provided without matching old field"
                            % column
                        )

                conn.execute(
                    "INSERT INTO stg_field "
                    "(seq, side, column, kind, val_int, val_blob, length, "
                    "hash) VALUES (?,?,?,?,?,?,?,?)",
                    (cur_seq, side, column, kind, val_int, None,
                     length, None),
                )
                cur_side, cur_column, cur_kind = side, column, kind
                cur_len, got_len, chunk_idx = length, 0, 0
                text_decoder = (
                    codecs.getincrementaldecoder("utf-8")(
                        errors="strict"
                    )
                    if kind == "text"
                    else None
                )
                hasher = (
                    hashlib.sha256()
                    if kind in ("text", "blob")
                    else None
                )
                state = "fieldbody"
                continue

            if keys == self._DATA_KEYS:
                if state != "fieldbody":
                    raise ValueError("data event outside a field")
                data = event["data"]
                if event["seq"] != cur_seq:
                    raise ValueError("data seq does not match field")
                if not isinstance(data, bytes) or len(data) > MAX_CHUNK:
                    raise ValueError(
                        "data must be bytes of at most %d bytes" % MAX_CHUNK
                    )
                if cur_kind not in ("text", "blob"):
                    raise ValueError("unset/null/int fields carry no data")
                if got_len + len(data) > cur_len:
                    raise ValueError("more data than declared length")
                if text_decoder is not None:
                    try:
                        text_decoder.decode(data)
                    except UnicodeError as exc:
                        raise ValueError("invalid UTF-8 text") from exc
                # Stream each bounded data block straight into a private
                # chunk row; the value is never assembled in Python memory.
                conn.execute(
                    "INSERT INTO stg_chunk "
                    "(seq, side, column, idx, piece) VALUES (?,?,?,?,?)",
                    (cur_seq, cur_side, cur_column, chunk_idx, data),
                )
                chunk_idx += 1
                hasher.update(data)
                got_len += len(data)
                continue

            if keys == self._SEQ_KEYS:
                if event["seq"] != cur_seq:
                    raise ValueError("end-of-field/op seq mismatch")
                if state == "fieldbody":
                    if got_len != cur_len:
                        raise ValueError(
                            "field ended before declared length reached"
                        )
                    if text_decoder is not None:
                        try:
                            text_decoder.decode(b"", final=True)
                        except UnicodeError as exc:
                            raise ValueError(
                                "invalid UTF-8 text"
                            ) from exc
                    if hasher is not None:
                        conn.execute(
                            "UPDATE stg_field SET hash=? "
                            "WHERE seq=? AND side=? AND column=?",
                            (hasher.digest(), cur_seq, cur_side, cur_column),
                        )
                    if cur_kind in ("text", "blob"):
                        self._materialize_blob(
                            conn, cur_seq, cur_side, cur_column
                        )
                    if cur_side == "old":
                        old_kinds[cur_column] = cur_kind
                    pair_idx += 1
                    state = (
                        "end" if pair_idx == len(pairs) else "field"
                    )
                    continue
                if state == "end":
                    state = "between"
                    continue
                raise ValueError("field_end/end in wrong position")

            raise ValueError(
                "event with illegal key set: %r" % sorted(keys)
            )

        if state != "between":
            raise ValueError("source ended in the middle of an operation")

    # -- whole-batch validation against the pre-batch image ---------------

    @staticmethod
    def _materialize_blob(conn, seq, side, column):
        """Rebuild one field body from its ordered chunk rows inside SQLite.

        The recursive CTE concatenates once per field in linear time and
        keeps the value a BLOB; empty text/blob becomes a zero-length BLOB.
        Nothing larger than a 64 KiB chunk ever crosses the Python boundary.
        """
        params = (seq, side, column) * 3
        conn.execute(
            "UPDATE stg_field SET val_blob = COALESCE(("
            " WITH RECURSIVE cat(acc, n) AS ("
            "  SELECT piece, idx FROM stg_chunk "
            "  WHERE seq=? AND side=? AND column=? AND idx=0"
            "  UNION ALL"
            "  SELECT acc || piece, ch.idx FROM stg_chunk ch JOIN cat"
            "   ON ch.idx = n + 1"
            "  WHERE ch.seq=? AND ch.side=? AND ch.column=?)"
            " SELECT CAST(acc AS BLOB) FROM cat ORDER BY n DESC LIMIT 1),"
            " zeroblob(0))"
            " WHERE seq=? AND side=? AND column=?",
            params,
        )
        # Chunk rows are no longer needed once the field body exists.
        conn.execute(
            "DELETE FROM stg_chunk WHERE seq=? AND side=? AND column=?",
            (seq, side, column),
        )

    def _validate_and_commit(self, conn):
        ops = conn.execute(
            "SELECT seq, op FROM stg_op ORDER BY seq"
        ).fetchall()

        # 1) Old ids across all delete/update operations must be unique.
        dup = conn.execute(
            "SELECT val_int FROM stg_field "
            "WHERE side='old' AND column='id' "
            "GROUP BY val_int HAVING COUNT(*) > 1"
        ).fetchall()
        if dup:
            raise ValueError(
                "duplicate old id in batch: %s"
                % ", ".join(str(r[0]) for r in dup)
            )

        moved_ids = set()
        final_rows = []  # (seq, final_id, op)

        # 2) Every delete/update must find its pre-batch row and match every
        #    provided old field; comparison runs byte-for-byte inside SQLite
        #    so large bodies never pass through Python memory.
        for seq, op in ops:
            if op == "insert":
                continue
            clauses = [
                "i.id = (SELECT val_int FROM stg_field "
                "WHERE seq=? AND side='old' AND column='id')"
            ]
            params = [seq]
            for column in ("tag", "payload"):
                kind = conn.execute(
                    "SELECT kind FROM stg_field "
                    "WHERE seq=? AND side='old' AND column=?",
                    (seq, column),
                ).fetchone()[0]
                if kind == "unset":
                    continue
                if kind == "null":
                    clauses.append("i.%s IS NULL" % column)
                elif column == "tag":
                    # Both sides are stored as BLOB so comparison is
                    # byte-for-byte; CAST is kept for robustness.
                    clauses.append(
                        "CAST(i.tag AS BLOB) = (SELECT val_blob FROM "
                        "stg_field WHERE seq=? AND side='old' "
                        "AND column='tag')"
                    )
                    params.append(seq)
                else:
                    clauses.append(
                        "i.payload = (SELECT val_blob FROM stg_field "
                        "WHERE seq=? AND side='old' AND column='payload')"
                    )
                    params.append(seq)
            found = conn.execute(
                "SELECT i.id FROM items i WHERE " + " AND ".join(clauses),
                params,
            ).fetchone()
            if found is None:
                raise ValueError(
                    "op seq %d: pre-batch row missing or old fields "
                    "mismatch" % seq
                )
            moved_ids.add(found[0])

        # 3) Final ids of insert/update must be unique among themselves and
        #    only reuse pre-batch ids released by this batch.
        for seq, op in ops:
            if op == "delete":
                continue
            row = conn.execute(
                "SELECT val_int FROM stg_field "
                "WHERE seq=? AND side='new' AND column='id' AND kind='int'",
                (seq,),
            ).fetchone()
            if row is not None:
                final_id = row[0]
            else:
                if op == "insert":
                    raise ValueError("insert requires a new id")
                final_id = conn.execute(
                    "SELECT val_int FROM stg_field "
                    "WHERE seq=? AND side='old' AND column='id'", (seq,)
                ).fetchone()[0]
            final_rows.append((seq, final_id, op))

        seen_final = set()
        for seq, final_id, op in final_rows:
            if final_id in seen_final:
                raise ValueError(
                    "final id %d produced by more than one operation"
                    % final_id
                )
            seen_final.add(final_id)
            if final_id not in moved_ids:
                occupied = conn.execute(
                    "SELECT 1 FROM items WHERE id=?", (final_id,)
                ).fetchone()
                if occupied is not None:
                    raise ValueError(
                        "final id %d occupies an unmoved pre-batch row"
                        % final_id
                    )

        # 4) Build the complete post-batch image in a private staging table.
        #    Inserts use the provided new values verbatim.
        conn.executemany(
            "INSERT INTO stg_final "
            "(id, tag, payload, tag_sha256, payload_sha256) "
            "SELECT (SELECT val_int FROM stg_field WHERE seq=? "
            "  AND side='new' AND column='id'), "
            "(SELECT val_blob FROM stg_field WHERE seq=? "
            "  AND side='new' AND column='tag'), "
            "(SELECT val_blob FROM stg_field WHERE seq=? "
            "  AND side='new' AND column='payload'), "
            "(SELECT hash FROM stg_field WHERE seq=? "
            "  AND side='new' AND column='tag'), "
            "(SELECT hash FROM stg_field WHERE seq=? "
            "  AND side='new' AND column='payload')",
            [(seq,) * 5 for seq, _id, op in final_rows if op == "insert"],
        )        # Updates overlay provided new values over the pre-batch row.
        # CASE on kind distinguishes an explicit NULL from UNSET, so NULL
        # really nulls the column while UNSET keeps the old value.
        for seq, final_id, op in final_rows:
            if op != "update":
                continue
            conn.execute(
                "INSERT INTO stg_final "
                "(id, tag, payload, tag_sha256, payload_sha256) "
                "SELECT ?, "
                " CASE (SELECT kind FROM stg_field WHERE seq=? AND side='new'"
                "  AND column='tag')"
                "   WHEN 'unset' THEN (SELECT CAST(tag AS BLOB) FROM items "
                "     WHERE id=(SELECT val_int FROM stg_field WHERE seq=? "
                "      AND side='old' AND column='id'))"
                "   WHEN 'null' THEN NULL ELSE (SELECT val_blob FROM "
                "     stg_field WHERE seq=? AND side='new' AND column='tag')"
                " END, "
                " CASE (SELECT kind FROM stg_field WHERE seq=? AND side='new'"
                "  AND column='payload')"
                "   WHEN 'unset' THEN (SELECT payload FROM items WHERE id="
                "     (SELECT val_int FROM stg_field WHERE seq=? AND "
                "      side='old' AND column='id'))"
                "   WHEN 'null' THEN NULL ELSE (SELECT val_blob FROM "
                "     stg_field WHERE seq=? AND side='new' "
                "     AND column='payload') END, "
                " CASE (SELECT kind FROM stg_field WHERE seq=? AND side='new'"
                "  AND column='tag')"
                "   WHEN 'unset' THEN (SELECT tag_sha256 FROM items_meta "
                "     WHERE id=(SELECT val_int FROM stg_field WHERE seq=? "
                "      AND side='old' AND column='id'))"
                "   WHEN 'null' THEN NULL ELSE (SELECT hash FROM stg_field "
                "     WHERE seq=? AND side='new' AND column='tag') END, "
                " CASE (SELECT kind FROM stg_field WHERE seq=? AND side='new'"
                "  AND column='payload')"
                "   WHEN 'unset' THEN (SELECT payload_sha256 FROM "
                "     items_meta WHERE id=(SELECT val_int FROM stg_field "
                "     WHERE seq=? AND side='old' AND column='id'))"
                "   WHEN 'null' THEN NULL ELSE (SELECT hash FROM stg_field "
                "     WHERE seq=? AND side='new' AND column='payload') END",
                (final_id,
                 seq, seq, seq,
                 seq, seq, seq,
                 seq, seq, seq,
                 seq, seq, seq),
            )

        # 5) Swap the main tables to the post-batch image; every statement
        #    is inside the single surrounding transaction.
        if moved_ids:
            marks = ",".join("?" for _ in moved_ids)
            conn.execute(
                "DELETE FROM items WHERE id IN (%s)" % marks,
                tuple(moved_ids),
            )
            conn.execute(
                "DELETE FROM items_meta WHERE id IN (%s)" % marks,
                tuple(moved_ids),
            )
        conn.execute(
            "INSERT INTO items (id, tag, payload) "
            "SELECT id, tag, payload FROM stg_final"
        )
        conn.execute(
            "INSERT INTO items_meta (id, tag_sha256, payload_sha256) "
            "SELECT id, tag_sha256, payload_sha256 FROM stg_final"
        )

        counts = {"inserted": 0, "updated": 0, "deleted": 0}
        for op, n in conn.execute(
            "SELECT op, COUNT(*) FROM stg_op GROUP BY op"
        ):
            counts[_COUNT_COLUMN[op]] = n
        return counts
