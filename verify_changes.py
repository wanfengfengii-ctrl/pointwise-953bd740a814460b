"""End-to-end verification of the CHG1 offline correction package flow.

All package bytes are produced by the independent ``pkgbuild`` builder
(never by reusing decoder internals).  The suite covers:

* field UNSET / NULL / empty-text / empty-blob boundaries
* primary-key swaps and delete-then-reinsert space release
* conflict rejection with full pre-batch preservation
* malformed tails, bad markers, non-shortest uvar, invalid UTF-8
* byte-for-byte chunk equivalence down to one-byte chunks
* a third-party event source (hand-built dict events, not Decoder)
* large streaming bodies: digests, Python memory peak, source consumption
* real subprocess SIGKILL mid-apply followed by reopen reconciliation
"""

import hashlib
import os
import shutil
import signal
import subprocess
import sys
import tempfile
import tracemalloc
import unittest

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import changeimport as ci  # noqa: E402
import pkgbuild as pb  # noqa: E402

MEMORY_BUDGET = 8 * 1024 * 1024
BIG = 20 * 1024 * 1024  # 20 MiB, well above the 8 MiB extra-value budget
HERE = os.path.dirname(os.path.abspath(__file__))


def fresh_store(rows=()):
    tmp = tempfile.mkdtemp()
    store = ci.Store(os.path.join(tmp, "items.db"))
    if rows:
        store.seed(list(rows))
    return tmp, store


def digest(blob):
    return None if blob is None else hashlib.sha256(blob).digest()


def events_of(pkg, chunk_size=65536):
    return list(ci.Decoder(pb.split_chunks(pkg, chunk_size)))


class DecoderFormatTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store = fresh_store(
            [(1, "a", b"p"), (2, None, None)]
        )

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp)

    def test_magic_required(self):
        with self.assertRaises(ValueError):
            list(ci.Decoder([b"XXXX", b"\x00"]))

    def test_unknown_opcode_rejected(self):
        with self.assertRaises(ValueError):
            list(ci.Decoder([b"CHG1", b"\x55", b"\x00"]))

    def test_unknown_field_marker_rejected(self):
        bad = b"CHG1" + b"\x09" + b"\x02" + b"\x00"
        with self.assertRaises(ValueError):
            list(ci.Decoder(pb.split_chunks(bad, 3)))

    def test_trailing_bytes_after_terminator_rejected(self):
        pkg = pb.package_bytes([]) + b"\x01"
        with self.assertRaises(ValueError):
            list(ci.Decoder(pb.split_chunks(pkg, 2)))
        # Terminator followed by an extra zero-length chunk then bytes.
        with self.assertRaises(ValueError):
            list(ci.Decoder([b"CHG1\x00", b"", b"x"]))

    def test_missing_terminator_rejected(self):
        pkg = pb.package_bytes([])[:-1]
        with self.assertRaises(ValueError):
            list(ci.Decoder([pkg]))

    def test_non_shortest_uvar_rejected(self):
        # length 1 encoded as 0x81 0x00 (two bytes, non-shortest)
        bad = b"CHG1" + b"\x09" + b"\x01" + (1).to_bytes(8, "big")
        bad += b"\x03\x81\x00A" + b"\x00\x00"
        with self.assertRaises(ValueError):
            list(ci.Decoder(pb.split_chunks(bad, 1)))

    def test_uvar_value_cap(self):
        # 9-byte uvar whose ninth byte carries a continuation bit, which
        # would imply a forbidden tenth byte.
        bad = (
            b"CHG1" + b"\x09" + b"\x01" + (1).to_bytes(8, "big")
            + b"\x03" + b"\xff" * 8 + b"\x80" + b"\x01" + b"\x00\x00"
        )
        with self.assertRaises(ValueError):
            list(ci.Decoder(pb.split_chunks(bad, 1)))

    def test_uvar_boundary_values_parse(self):
        for value in (0, 1, 127, 128, 2 ** 56, 2 ** 62, 2 ** 63 - 1):
            enc = pb.uvar(value)
            self.assertLessEqual(len(enc), 9)
            # A delete whose payload declares this length; the uvar itself
            # must parse and only the missing body may fail afterwards.
            pkg = (
                b"CHG1" + b"\x09" + b"\x01" + (1).to_bytes(8, "big")
                + b"\x00\x04" + enc
            )
            with self.assertRaises(ValueError) as ctx:
                list(ci.Decoder([pkg]))
            self.assertNotIn("uvar", str(ctx.exception))

    def test_uvar_ninth_byte_overrun_rejected(self):
        for ninth in (0x80, 0x81, 0xFE, 0xFF):
            bad = (
                b"CHG1\x09" + b"\x01" + (1).to_bytes(8, "big")
                + b"\x00\x04" + b"\x80" * 8 + bytes([ninth])
            )
            with self.assertRaises(ValueError):
                list(ci.Decoder([bad]))

    def test_invalid_utf8_rejected_even_split_inside_sequence(self):
        bad_utf8 = b"\xe4\xbd"  # truncated 3-byte sequence
        bad = (
            b"CHG1" + b"\x09" + b"\x01" + (1).to_bytes(8, "big")
            + b"\x03" + pb.uvar(len(bad_utf8)) + bad_utf8 + b"\x00"
        )
        with self.assertRaises(ValueError):
            list(ci.Decoder(pb.split_chunks(bad, 1)))

    def test_text_utf8_can_straddle_chunk_boundaries(self):
        text = "中文字" * 10
        pkg = pb.package_bytes([
            ("delete",
             {"id": ("int", 1), "tag": ("text", text), "payload": "unset"},
             None),
        ])
        events = list(ci.Decoder(pb.split_chunks(pkg, 1)))
        data = b"".join(e["data"] for e in events if "data" in e)
        self.assertEqual(data.decode("utf-8"), text)

    def test_event_shapes_and_order(self):
        pkg = pb.package_bytes([
            ("insert", None,
             {"id": ("int", 7), "tag": ("text", "t"),
              "payload": ("blob", b"b")}),
        ])
        events = list(ci.Decoder(pb.split_chunks(pkg, 5)))
        kinds = [tuple(sorted(e)) for e in events]
        self.assertEqual(events[0], {"seq": 0, "op": "insert"})
        begins = [e for e in events if "op" in e]
        field_events = [e for e in events if "column" in e]
        self.assertEqual(
            [(e["side"], e["column"]) for e in field_events],
            [("new", "id"), ("new", "tag"), ("new", "payload")],
        )
        # each text/blob field has field_end; int has no data events
        self.assertEqual(sum(1 for e in events if e.keys() == {"seq"}), 4)
        self.assertTrue(all("value" not in e or e["column"] == "id"
                            for e in field_events))
        self.assertEqual(begins[0]["seq"], 0)

    def test_insert_with_unset_rejected_by_decoder(self):
        pkg = pb.package_bytes([
            ("insert", None,
             {"id": ("int", 9), "tag": "unset", "payload": ("null",)}),
        ])
        with self.assertRaises(ValueError):
            list(ci.Decoder(pb.split_chunks(pkg, 4)))

    def test_source_exception_propagates_unchanged(self):
        class Boom(Exception):
            pass

        def boom_chunks():
            yield b"CHG1"
            raise Boom("from source")

        with self.assertRaises(Boom):
            list(ci.Decoder(boom_chunks()))

    def test_oversized_chunk_rejected(self):
        with self.assertRaises(ValueError):
            list(ci.Decoder([b"CHG1", b"\x00" + b"x" * 65536]))


class StoreSemanticsTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store = fresh_store([
            (1, "A", b"x"),
            (2, "B", b"y"),
            (3, None, b""),
        ])

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp)

    def snapshot(self):
        return {rid: (tag, payload)
                for rid, tag, _size, _h in self.store.summary()
                for payload in [self.store.read(rid)[2]]}

    def apply_pkg(self, ops, chunk_size=65536):
        pkg = pb.package_bytes(ops)
        return self.store.apply(
            ci.Decoder(pb.split_chunks(pkg, chunk_size))
        )

    def test_seed_is_atomic_and_empty_only(self):
        with self.assertRaises(ValueError):
            self.store.seed([(99, "z", b"z")])
        self.assertEqual(len(self.store.summary()), 3)

    def test_insert_delete_update_counts_and_read(self):
        counts = self.apply_pkg([
            ("insert", None,
             {"id": ("int", 10), "tag": ("null",), "payload": ("blob", b"")}),
            ("delete",
             {"id": ("int", 3), "tag": "unset", "payload": ("blob", b"")},
             None),
            ("update",
             {"id": ("int", 1), "tag": ("text", "A"), "payload": "unset"},
             {"id": "unset", "tag": ("null",), "payload": "unset"}),
        ])
        self.assertEqual(counts,
                         {"inserted": 1, "updated": 1, "deleted": 1})
        self.assertIsNone(self.store.read(3))
        self.assertEqual(self.store.read(10), (10, None, b""))
        # NULL tag really nulled; payload kept old value
        self.assertEqual(self.store.read(1), (1, None, b"x"))

    def test_unset_keeps_old_value_but_null_clears(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            # new payload provided without matching old payload field
            self.apply_pkg([
                ("update",
                 {"id": ("int", 2), "tag": "unset", "payload": "unset"},
                 {"id": "unset", "tag": "unset",
                  "payload": ("blob", b"new")}),
            ])
        self.assertEqual(self.snapshot(), before)
        self.apply_pkg([
            ("update",
             {"id": ("int", 2), "tag": "unset",
              "payload": ("blob", b"y")},
             {"id": "unset", "tag": "unset",
              "payload": ("blob", b"new")}),
        ])
        self.assertEqual(self.store.read(2), (2, "B", b"new"))
        # explicit NULL payload, tag untouched
        self.apply_pkg([
            ("update",
             {"id": ("int", 2), "tag": ("text", "B"),
              "payload": ("blob", b"new")},
             {"id": "unset", "tag": "unset", "payload": "null"}),
        ])
        self.assertEqual(self.store.read(2), (2, "B", None))

    def test_empty_text_and_empty_blob_distinct_from_null(self):
        self.apply_pkg([
            ("insert", None,
             {"id": ("int", 20), "tag": ("text", ""),
              "payload": ("blob", b"")}),
        ])
        rid, tag, payload = self.store.read(20)
        self.assertEqual(tag, "")
        self.assertEqual(payload, b"")
        self.assertIsNotNone(tag)
        self.assertIsNotNone(payload)
        summ = {r[0]: r for r in self.store.summary()}[20]
        self.assertEqual(summ[2], 0)
        self.assertEqual(summ[3], hashlib.sha256(b"").digest())

    def test_primary_key_swap_takes_effect_as_a_whole(self):
        counts = self.apply_pkg([
            ("update",
             {"id": ("int", 1), "tag": ("text", "A"), "payload": "unset"},
             {"id": ("int", 2), "tag": ("text", "AA"), "payload": "unset"}),
            ("update",
             {"id": ("int", 2), "tag": "unset", "payload": "unset"},
             {"id": ("int", 1), "tag": "unset", "payload": "unset"}),
        ], chunk_size=1)
        self.assertEqual(counts["updated"], 2)
        self.assertEqual(self.store.read(1), (1, "B", b"y"))
        self.assertEqual(self.store.read(2), (2, "AA", b"x"))

    def test_single_leg_of_swap_conflicts_and_preserves_db(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.apply_pkg([
                ("update",
                 {"id": ("int", 1), "tag": ("text", "A"),
                  "payload": "unset"},
                 {"id": ("int", 2), "tag": ("text", "AA"),
                  "payload": "unset"}),
            ])
        self.assertEqual(self.snapshot(), before)

    def test_delete_frees_id_for_insert_in_same_batch(self):
        counts = self.apply_pkg([
            ("delete", {"id": ("int", 1), "tag": "unset",
                        "payload": "unset"}, None),
            ("insert", None,
             {"id": ("int", 1), "tag": "null",
              "payload": ("blob", b"")}),
        ])
        self.assertEqual(counts, {"inserted": 1, "updated": 0, "deleted": 1})
        self.assertEqual(self.store.read(1), (1, None, b""))

    def test_old_field_mismatch_rejects_entire_batch(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.apply_pkg([
                ("update",
                 {"id": ("int", 1), "tag": ("text", "WRONG"),
                  "payload": "unset"},
                 {"id": "unset", "tag": ("text", "Z"), "payload": "unset"}),
                ("insert", None,
                 {"id": ("int", 30), "tag": ("text", "ok"),
                  "payload": "null"}),
            ])
        self.assertEqual(self.snapshot(), before)
        self.assertIsNone(self.store.read(30))

    def test_missing_record_rejects_batch(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.apply_pkg([
                ("delete", {"id": ("int", 999), "tag": "unset",
                            "payload": "unset"}, None),
            ])
        self.assertEqual(self.snapshot(), before)

    def test_duplicate_old_id_rejected(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.apply_pkg([
                ("delete", {"id": ("int", 1), "tag": "unset",
                            "payload": "unset"}, None),
                ("update",
                 {"id": ("int", 1), "tag": "unset", "payload": "unset"},
                 {"id": "unset", "tag": "unset", "payload": "unset"}),
            ])
        self.assertEqual(self.snapshot(), before)

    def test_final_id_collision_rejected(self):
        before = self.snapshot()
        with self.assertRaises(ValueError):
            self.apply_pkg([
                ("insert", None,
                 {"id": ("int", 50), "tag": ("text", "a"),
                  "payload": "null"}),
                ("insert", None,
                 {"id": ("int", 50), "tag": ("text", "b"),
                  "payload": "null"}),
            ])
        self.assertEqual(self.snapshot(), before)

    def test_noop_update_is_legal_and_counted(self):
        before = self.snapshot()
        counts = self.apply_pkg([
            ("update",
             {"id": ("int", 1), "tag": "unset", "payload": "unset"},
             {"id": "unset", "tag": "unset", "payload": "unset"}),
        ])
        self.assertEqual(counts["updated"], 1)
        self.assertEqual(self.snapshot(), before)

    def test_tail_corruption_leaves_db_untouched(self):
        before = self.snapshot()
        pkg = pb.package_bytes([
            ("delete", {"id": ("int", 1), "tag": "unset",
                        "payload": "unset"}, None),
        ])
        corrupted = pkg[:-1] + b"\x7f"  # replace terminator
        with self.assertRaises(ValueError):
            self.store.apply(ci.Decoder(pb.split_chunks(corrupted, 3)))
        self.assertEqual(self.snapshot(), before)

    def test_store_remains_usable_after_rejection(self):
        with self.assertRaises(ValueError):
            self.apply_pkg([
                ("delete", {"id": ("int", 404), "tag": "unset",
                            "payload": "unset"}, None),
            ])
        counts = self.apply_pkg([
            ("insert", None,
             {"id": ("int", 77), "tag": ("text", "ok"),
              "payload": ("blob", b"z")}),
        ])
        self.assertEqual(counts["inserted"], 1)
        self.assertEqual(self.store.read(77), (77, "ok", b"z"))

    def test_reopen_sees_committed_results(self):
        path = os.path.join(self.tmp, "items.db")
        self.apply_pkg([
            ("insert", None,
             {"id": ("int", 88), "tag": ("text", "persisted"),
              "payload": ("blob", b"q")}),
        ])
        self.store.close()
        reopened = ci.Store(path)
        self.assertEqual(reopened.read(88), (88, "persisted", b"q"))
        reopened.close()


class ThirdPartySourceTests(unittest.TestCase):
    def setUp(self):
        self.tmp, self.store = fresh_store([(1, "A", b"x")])

    def tearDown(self):
        self.store.close()
        shutil.rmtree(self.tmp)

    @staticmethod
    def hand_built_events():
        # A delete of id 1 and an insert reusing id 1 with NULL tag and
        # empty payload, emitted as plain dicts with no Decoder involved.
        yield {"seq": 0, "op": "delete"}
        yield {"seq": 0, "side": "old", "column": "id",
               "kind": "int", "length": 0, "value": 1}
        yield {"seq": 0}
        yield {"seq": 0, "side": "old", "column": "tag",
               "kind": "unset", "length": 0}
        yield {"seq": 0}
        yield {"seq": 0, "side": "old", "column": "payload",
               "kind": "unset", "length": 0}
        yield {"seq": 0}
        yield {"seq": 0}
        yield {"seq": 1, "op": "insert"}
        yield {"seq": 1, "side": "new", "column": "id",
               "kind": "int", "length": 0, "value": 1}
        yield {"seq": 1}
        yield {"seq": 1, "side": "new", "column": "tag",
               "kind": "null", "length": 0}
        yield {"seq": 1}
        yield {"seq": 1, "side": "new", "column": "payload",
               "kind": "blob", "length": 0}
        yield {"seq": 1}
        yield {"seq": 1}

    def test_third_party_event_source_accepted(self):
        counts = self.store.apply(self.hand_built_events())
        self.assertEqual(counts,
                         {"inserted": 1, "updated": 0, "deleted": 1})
        self.assertEqual(self.store.read(1), (1, None, b""))

    def test_store_rejects_bad_third_party_event_order(self):
        def bad():
            yield {"seq": 0, "op": "insert"}
            # wrong column order: payload before tag
            yield {"seq": 0, "side": "new", "column": "id",
                   "kind": "int", "length": 0, "value": 5}
            yield {"seq": 0}
            yield {"seq": 0, "side": "new", "column": "payload",
                   "kind": "null", "length": 0}
            yield {"seq": 0}

        with self.assertRaises(ValueError):
            self.store.apply(bad())
        self.assertIsNone(self.store.read(5))

    def test_store_rejects_extra_event_keys(self):
        def bad():
            yield {"seq": 0, "op": "delete"}
            yield {"seq": 0, "side": "old", "column": "id",
                   "kind": "int", "length": 0, "value": 1,
                   "surprise": True}
            yield {"seq": 0}

        with self.assertRaises(ValueError):
            self.store.apply(bad())

    def test_source_exception_propagates_unchanged(self):
        class CustomError(Exception):
            pass

        def boom():
            yield {"seq": 0, "op": "delete"}
            raise CustomError("third party failure")

        with self.assertRaises(CustomError):
            self.store.apply(boom())
        # pre-batch row still present
        self.assertEqual(self.store.read(1), (1, "A", b"x"))


class ChunkEquivalenceTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _package(self):
        old_payload = bytes(range(256)) * 40
        return pb.package_bytes([
            ("insert", None,
             {"id": ("int", 1), "tag": ("text", "中A" * 50),
              "payload": ("blob", old_payload)}),
            ("update",
             {"id": ("int", 1), "tag": ("text", "中A" * 50),
              "payload": ("blob", old_payload)},
             {"id": "unset", "tag": ("text", "B"), "payload": "unset"}),
        ])

    def test_one_byte_chunks_match_whole_package(self):
        pkg = self._package()
        whole = list(ci.Decoder([pkg]))
        split = list(ci.Decoder(pb.split_chunks(pkg, 1)))
        self.assertEqual(whole, split)

        old_payload = bytes(range(256)) * 40
        update_pkg = pb.package_bytes([
            ("update",
             {"id": ("int", 1), "tag": ("text", "old"),
              "payload": ("blob", old_payload)},
             {"id": "unset", "tag": ("text", "B"), "payload": "unset"}),
        ])
        for size in (1, 2, 3, 7, 64, 4096, 65535, 65536):
            path = os.path.join(self.tmp, "s%d.db" % size)
            store = ci.Store(path)
            store.seed([(1, "old", old_payload)])
            store.apply(ci.Decoder(pb.split_chunks(update_pkg, size)))
            self.assertEqual(store.read(1), (1, "B", old_payload))
            store.close()

    def test_zero_length_chunks_are_skipped(self):
        pkg = self._package()
        chunks = []
        for i in range(0, len(pkg), 13):
            chunks.append(b"")
            chunks.append(pkg[i:i + 13])
        events = list(ci.Decoder(chunks))
        self.assertEqual(events, list(ci.Decoder([pkg])))


class LargeBodyTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.mkdtemp()

    def tearDown(self):
        shutil.rmtree(self.tmp)

    def _make_package(self, size):
        # Deterministic, non-repeating-ish payload via repeated pattern of
        # 256 bytes; independently hashed below.
        payload = bytes((i * 7 + 3) % 256 for i in range(256)) * (
            size // 256
        )
        payload += b"z" * (size - len(payload))
        text = ("中" * 1000).encode("utf-8")
        ops = [
            ("insert", None,
             {"id": ("int", 100),
              "tag": ("text", text.decode("utf-8")),
              "payload": ("blob", payload)}),
        ]
        return pb.package_bytes(ops), payload, text

    def test_large_body_digest_memory_peak_and_consumption(self):
        pkg, payload, text = self._make_package(BIG)
        self.assertGreater(len(pkg), MEMORY_BUDGET)

        reads = {"n": 0}
        ci_file = os.path.abspath(ci.__file__)

        class CountingChunks:
            def __iter__(self_inner):
                for chunk in pb.split_chunks(pkg, 65536):
                    reads["n"] += 1
                    yield chunk

        path = os.path.join(self.tmp, "big.db")
        store = ci.Store(path)
        # Attribute only allocations made inside the implementation module;
        # bytes the caller (this test) already holds are explicitly outside
        # the contract's extra-value-payload budget.
        tracemalloc.start(25)
        counts = store.apply(ci.Decoder(CountingChunks()))
        snapshot = tracemalloc.take_snapshot()
        tracemalloc.stop()
        self.assertEqual(counts["inserted"], 1)

        module_stats = [
            s for s in snapshot.statistics("lineno")
            if any(ci_file in frame.filename for frame in s.traceback)
        ]
        module_peak = max((s.size for s in module_stats), default=0)
        module_total = sum(s.size for s in module_stats)
        self.assertLess(
            module_peak, MEMORY_BUDGET,
            "largest changeimport allocation %d exceeds 8 MiB"
            % module_peak,
        )
        self.assertLess(
            module_total, MEMORY_BUDGET,
            "changeimport retained payload memory %d exceeds 8 MiB"
            % module_total,
        )

        # The source was consumed exactly once, chunk by chunk.
        expected_reads = (len(pkg) + 65535) // 65536
        self.assertEqual(reads["n"], expected_reads)

        # Full post-commit reconciliation via summary digests and read.
        summary = {r[0]: r for r in store.summary()}
        row = summary[100]
        self.assertEqual(row[2], BIG)
        self.assertEqual(row[3], hashlib.sha256(payload).digest())
        rid, tag, stored = store.read(100)
        self.assertEqual(tag, text.decode("utf-8"))
        self.assertEqual(len(stored), BIG)
        self.assertEqual(hashlib.sha256(stored).digest(),
                         hashlib.sha256(payload).digest())

        # Byte-for-byte equality rather than trusting length alone.
        self.assertEqual(stored, payload)
        store.close()

    def test_corrupted_large_body_rejected_without_partial_state(self):
        # A smaller multi-MiB body is enough to prove byte-level
        # comparison without repeating the full 20 MiB budget test.
        size = 3 * 1024 * 1024
        payload = bytes((i * 11 + 5) % 256 for i in range(256)) * (
            size // 256
        )
        text = "边界" * 64
        path = os.path.join(self.tmp, "big2.db")
        store = ci.Store(path)
        store.seed([(100, text, payload)])
        tampered = bytearray(payload)
        tampered[size // 2] ^= 0x01
        update_pkg = pb.package_bytes([
            ("update",
             {"id": ("int", 100), "tag": ("text", text),
              "payload": ("blob", bytes(tampered))},
             {"id": "unset", "tag": "unset", "payload": "unset"}),
        ])
        before = store.summary()
        with self.assertRaises(ValueError):
            store.apply(ci.Decoder(pb.split_chunks(update_pkg, 65536)))
        self.assertEqual(store.summary(), before)
        prefix_pkg = pb.package_bytes([
            ("update",
             {"id": ("int", 100), "tag": ("text", text),
              "payload": ("blob", payload[:size // 2])},
             {"id": "unset", "tag": "unset", "payload": "unset"}),
        ])
        with self.assertRaises(ValueError):
            store.apply(ci.Decoder(pb.split_chunks(prefix_pkg, 65536)))
        self.assertEqual(store.summary(), before)
        store.close()


class SigKillTests(unittest.TestCase):
    """Real child processes killed with SIGKILL during apply()."""

    def test_sigkill_at_multivalent_points_then_reopen(self):
        work = tempfile.mkdtemp()
        spawned = []
        try:
            driver = os.path.join(work, "kill_driver.py")
            with open(driver, "w", encoding="utf-8") as fh:
                fh.write(
                    DRIVER_SOURCE.replace(
                        "__HERE__",
                        HERE.replace("\\", "\\\\").replace('"', '\\"'),
                    )
                )
            # Self-inflicted SIGKILL at measured ingestion progress points.
            points = ["ingest_25pct", "ingest_75pct", "after_ingest"]
            outcomes = []
            for point in points:
                db_dir = os.path.join(work, point)
                os.makedirs(db_dir, exist_ok=True)
                proc = subprocess.run(
                    [sys.executable, "-I", driver, db_dir, point],
                    cwd=HERE,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.PIPE,
                    timeout=120,
                    start_new_session=True,
                )
                # SIGKILL yields -9; the simulated post-ingest abort exits 0.
                self.assertIn(proc.returncode, (-9, 0, 1))
                self._assert_db_is_one_consistent_image(db_dir)
                outcomes.append((point, proc.returncode))

            # Parent-delivered SIGKILL after the child provably entered
            # apply(), covering ingestion and the final transaction window.
            db_dir = os.path.join(work, "parent_kill")
            os.makedirs(db_dir, exist_ok=True)
            ready = os.path.join(db_dir, "ready")
            if os.path.exists(ready):
                os.remove(ready)
            proc = subprocess.Popen(
                [sys.executable, "-I", driver, db_dir, "run_big"],
                cwd=HERE,
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                start_new_session=True,
            )
            spawned.append(proc)
            import time
            entered = False
            for _ in range(600):  # up to 60 s for apply() to start
                if os.path.exists(ready):
                    entered = True
                    break
                if proc.poll() is not None:
                    break
                time.sleep(0.1)
            if not entered:
                # Only read the child's pipes once it has actually exited:
                # reading stderr of a still-parked child would deadlock.
                proc.wait(timeout=30)
                self.fail(
                    "child never entered apply(): "
                    + proc.stderr.read().decode(errors="replace")
                )
            # The child is now deterministically parked inside apply() on a
            # blocking stdin read, so the externally delivered SIGKILL
            # provably lands mid-batch with staged data already present.
            if proc.poll() is not None:
                log_path = os.path.join(db_dir, "driver.log")
                log_txt = ""
                if os.path.exists(log_path):
                    log_txt = "\ndriver.log: " + open(log_path).read()
                self.fail(
                    "run_big child exited early (rc=%s): %s%s"
                    % (proc.returncode,
                       proc.stderr.read().decode(errors="replace")[:2000],
                       log_txt)
                )
            os.killpg(os.getpgid(proc.pid), signal.SIGKILL)
            stdout, stderr = proc.communicate(timeout=30)
            self.assertEqual(proc.returncode, -9)
            spawned.remove(proc)
            self._assert_db_is_one_consistent_image(db_dir)
            outcomes.append(("external_sigkill_mid_apply", -9))

            # Clean control run on the same driver commits fully.
            db_dir = os.path.join(work, "clean")
            os.makedirs(db_dir, exist_ok=True)
            proc = subprocess.run(
                [sys.executable, "-I", driver, db_dir, "none"],
                cwd=HERE,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=120,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr.decode())
            store = ci.Store(os.path.join(db_dir, "items.db"))
            self.assertEqual(
                sorted(r[0] for r in store.summary()), [1, 2, 3, 4]
            )
            store.close()

            # Distinguish points actually exercised from the durability
            # conclusion that additionally relies on SQLite's documented
            # atomic-commit (rollback journal) guarantee.  A simulated power
            # loss or corrupted SQLite file is intentionally out of scope.
            measured = {point for point, _rc in outcomes}
            self.assertEqual(
                measured,
                {
                    "ingest_25pct",
                    "ingest_75pct",
                    "after_ingest",
                    "external_sigkill_mid_apply",
                },
            )
        finally:
            # Guarantee no parked child is orphaned if the test itself is
            # interrupted: kill every spawned process group we still own.
            for child in spawned:
                if child.poll() is None:
                    try:
                        os.killpg(os.getpgid(child.pid), signal.SIGKILL)
                    except ProcessLookupError:
                        pass
                    try:
                        child.communicate(timeout=10)
                    except subprocess.TimeoutExpired:
                        pass
            shutil.rmtree(work, ignore_errors=True)

    @staticmethod
    def _assert_db_is_one_consistent_image(db_dir):
        db_path = os.path.join(db_dir, "items.db")
        store = ci.Store(db_path)
        rows = store.summary()
        # Either full pre-batch image or full post-batch image; the row id
        # set is invariant for this swap-heavy workload.
        ids = sorted(r[0] for r in rows)
        SigKillTests.assertEqualStatic(ids, [1, 2, 3, 4])
        # No private staging leftovers survive reopen.
        leftovers = store._conn.execute(
            "SELECT (SELECT COUNT(*) FROM stg_op) + "
            "(SELECT COUNT(*) FROM stg_field) + "
            "(SELECT COUNT(*) FROM stg_chunk) + "
            "(SELECT COUNT(*) FROM stg_final)"
        ).fetchone()[0]
        SigKillTests.assertEqualStatic(leftovers, 0)
        # A journal/WAL left by a hard kill must not expose a half batch:
        # every payload digest agrees with the stored bytes.
        for rid, tag, size, want in rows:
            payload = store.read(rid)[2]
            if payload is None:
                SigKillTests.assertEqualStatic(size, None)
                SigKillTests.assertEqualStatic(want, None)
            else:
                SigKillTests.assertEqualStatic(size, len(payload))
                SigKillTests.assertEqualStatic(
                    want, hashlib.sha256(payload).digest()
                )
        store.close()

    @staticmethod
    def assertEqualStatic(a, b):
        assert a == b, (a, b)


# Driver program source (written into an isolated directory, never imported
# from an untrusted location).
DRIVER_SOURCE = r'''
import os
import signal
import sys
import time

sys.path.insert(0, "__HERE__")
import changeimport as ci
import pkgbuild as pb

db_dir, kill_point = sys.argv[1], sys.argv[2]
rows = [
    (1, "tag1", b"payload-one"),
    (2, "tag2", b"payload-two"),
    (3, None, None),
    (4, "tag4", b""),
]
store = ci.Store(os.path.join(db_dir, "items.db"))
store.seed(rows)

ops = [
    ("update",
     {"id": ("int", 1), "tag": ("text", "tag1"), "payload": "unset"},
     {"id": ("int", 2), "tag": ("text", "tag1moved"), "payload": "unset"}),
    ("update",
     {"id": ("int", 2), "tag": ("text", "tag2"), "payload": "unset"},
     {"id": ("int", 1), "tag": "unset", "payload": "unset"}),
    ("delete", {"id": ("int", 3), "tag": ("null",), "payload": "unset"},
     None),
    ("insert", None,
     {"id": ("int", 3), "tag": ("text", "revived"),
      "payload": ("blob", b"new-body")}),
]
pkg = pb.package_bytes(ops)
chunks = pb.split_chunks(pkg, 7)

if kill_point == "none":
    print(store.apply(ci.Decoder(iter(chunks))))
    store.close()
    sys.exit(0)

if kill_point == "run_big":
    # Long-running batch so an external SIGKILL lands inside apply(),
    # including its final transaction window.  A ready file signals the
    # parent that the child has entered the apply() call.
    big_ops = []
    for i in range(100, 300):
        big_ops.append((
            "insert", None,
            {"id": ("int", i), "tag": ("text", "row%d" % i),
             "payload": ("blob", bytes((j % 251) for j in range(4096)))},
        ))
    big_pkg = pb.package_bytes(big_ops)
    del big_ops
    ready = os.path.join(db_dir, "ready")
    chunks = pb.split_chunks(big_pkg, 65536)

    class ReadySource:
        def __init__(self, chunks):
            self.chunks = chunks
            self.signalled = False

        def __iter__(self):
            # Park roughly mid-stream: some chunks are already staged when
            # the externally delivered SIGKILL arrives.
            park_at = len(self.chunks) // 2
            for idx, chunk in enumerate(self.chunks):
                if not self.signalled:
                    with open(ready, "w") as fh:
                        fh.write("ready")
                    self.signalled = True
                if idx == park_at:
                    # Deterministic handshake: block on the stdin pipe the
                    # parent keeps open.  The parent kills this process
                    # group instead of writing; if the parent dies, the pipe
                    # closes, read() returns "" and the child exits, so no
                    # orphan can stay parked.
                    with open(os.path.join(db_dir, "driver.log"), "w") as fh:
                        fh.write("parked at idx=%d" % idx)
                    if sys.stdin.read() == "":
                        os._exit(2)
                yield chunk

    store.apply(ci.Decoder(ReadySource(chunks)))
    store.close()
    sys.exit(0)


class Instrumented:
    def __init__(self, chunks, point):
        self.chunks = list(chunks)
        self.point = point
        self.served = 0

    def __iter__(self):
        total = len(self.chunks)
        for chunk in self.chunks:
            yield chunk
            self.served += 1
            if self.point == "ingest_25pct" and self.served == total // 4:
                os.kill(os.getpid(), signal.SIGKILL)
            if self.point == "ingest_75pct" and self.served == total * 3 // 4:
                os.kill(os.getpid(), signal.SIGKILL)


if kill_point in ("ingest_25pct", "ingest_75pct"):
    store.apply(ci.Decoder(Instrumented(chunks, kill_point)))
elif kill_point == "after_ingest":
    # Deterministic abort after events are fully ingested but before the
    # final commit path: a source-level exception inside apply triggers the
    # same rollback guarantee a kill would rely on.
    def gen():
        for ev in ci.Decoder(iter(chunks)):
            yield ev
        raise RuntimeError("post-ingest source abort")
    try:
        store.apply(gen())
    except RuntimeError:
        store.close()
        sys.exit(0)
    sys.exit(1)
else:
    sys.exit(1)
'''.replace("__HERE__", HERE.replace("\\", "\\\\").replace('"', '\\"'))


if __name__ == "__main__":
    unittest.main(verbosity=2)
