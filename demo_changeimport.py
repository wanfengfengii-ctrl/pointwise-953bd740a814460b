"""Runnable demonstration of the CHG1 correction-package workflow.

It builds a small warehouse, streams an independently encoded correction
package through one-byte chunks, shows a legal primary-key swap and a
delete-then-reinsert taking effect as one batch, then reconciles the
post-commit database byte-for-byte against the expected image.  A
deliberately conflicting batch is also shown to leave the database
untouched.
"""

import hashlib
import os
import shutil
import sys
import tempfile

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

import changeimport as ci  # noqa: E402
import pkgbuild as pb  # noqa: E402


def h(blob):
    return None if blob is None else hashlib.sha256(blob).hexdigest()[:12]


def show(store, title):
    print(title)
    for rid, tag, size, digest in store.summary():
        payload = store.read(rid)[2]
        kind = "NULL" if payload is None else "%d bytes" % size
        print("  id=%-3d tag=%-8r payload=%-9s sha256=%s"
              % (rid, tag, kind, h(payload)))


def encode(operations):
    return pb.package_bytes(operations)


def main():
    work = tempfile.mkdtemp(prefix="changeimport-demo-")
    try:
        db_path = os.path.join(work, "items.db")
        store = ci.Store(db_path)
        store.seed([
            (1, "A", b"payload-one"),
            (2, "B", b"payload-two"),
            (3, None, None),
        ])
        show(store, "Pre-batch image:")

        # Batch 1: legal primary-key swap (1 -> 2, 2 -> 1) plus a delete of
        # id 3 immediately followed by reinserting id 3 in the same batch.
        swap_batch = encode([
            ("update",
             {"id": ("int", 1), "tag": ("text", "A"),
              "payload": ("blob", b"payload-one")},
             {"id": ("int", 2), "tag": ("text", "A-on-2"),
              "payload": "unset"}),
            ("update",
             {"id": ("int", 2), "tag": ("text", "B"),
              "payload": ("blob", b"payload-two")},
             {"id": ("int", 1), "tag": "unset", "payload": "unset"}),
            ("delete",
             {"id": ("int", 3), "tag": "null", "payload": "unset"},
             None),
            ("insert", None,
             {"id": ("int", 3), "tag": ("text", "revived"),
              "payload": ("blob", b"fresh-body")}),
        ])
        counts = store.apply(
            ci.Decoder(pb.split_chunks(swap_batch, 1))
        )
        print("\nApplied swap batch over one-byte chunks:", counts)
        show(store, "Post-batch image:")

        expected = {
            1: (1, "B", b"payload-two"),
            2: (2, "A-on-2", b"payload-one"),
            3: (3, "revived", b"fresh-body"),
        }
        for rid, want in expected.items():
            got = store.read(rid)
            assert got == want, (rid, got, want)
        print("\nByte-for-byte reconciliation: all 3 rows match expected image")

        # Batch 2: the same swap with only one leg must conflict and leave
        # every pre-batch record untouched.
        before = store.summary()
        conflict = encode([
            ("update",
             {"id": ("int", 1), "tag": ("text", "B"),
              "payload": ("blob", b"payload-two")},
             {"id": ("int", 2), "tag": ("text", "clash"),
              "payload": "unset"}),
        ])
        try:
            store.apply(ci.Decoder(pb.split_chunks(conflict, 5)))
        except ValueError as exc:
            print("\nConflicting single-leg batch rejected:", exc)
        assert store.summary() == before
        print("Database unchanged after rejection (count=%d rows)"
              % len(before))

        # Reopen proves the committed result is durable.
        store.close()
        reopened = ci.Store(db_path)
        assert reopened.read(2) == (2, "A-on-2", b"payload-one")
        print("Reopen check: id 2 still (2, 'A-on-2', b'payload-one')")
        reopened.close()
        print("\nDemo finished; database at", db_path)
    finally:
        shutil.rmtree(work, ignore_errors=True)


if __name__ == "__main__":
    main()
