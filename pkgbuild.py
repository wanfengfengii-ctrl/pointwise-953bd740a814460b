"""Independent CHG1 byte-package builder used only by tests and demos.

The encoding here is written straight from the wire description in
CONTRACT.md and never imports or peeks at ``changeimport.Decoder``, so an
end-to-end round trip genuinely exercises two independent implementations.
"""

MAGIC = b"CHG1"
OPCODES = {"insert": 0x12, "delete": 0x09, "update": 0x17}
MARKERS = {"unset": 0, "int": 1, "text": 3, "blob": 4, "null": 5}


def uvar(value):
    """Shortest unsigned LEB128 for 0 <= value <= 2**63-1."""
    if value < 0:
        raise ValueError("uvar needs a non-negative value")
    out = bytearray()
    while True:
        b = value & 0x7F
        value >>= 7
        if value:
            out.append(b | 0x80)
        else:
            out.append(b)
            return bytes(out)


def field_bytes(kind, value=None):
    """Encode one field independently of the decoder."""
    if kind not in MARKERS:
        raise ValueError("unknown kind %r" % (kind,))
    out = bytearray((MARKERS[kind],))
    if kind == "unset" or kind == "null":
        return bytes(out)
    if kind == "int":
        if isinstance(value, bool) or not isinstance(value, int):
            raise ValueError("int field needs a non-bool integer")
        out += value.to_bytes(8, "big", signed=True)
        return bytes(out)
    if kind == "text":
        body = value.encode("utf-8") if isinstance(value, str) else bytes(value)
    else:
        body = bytes(value)
    out += uvar(len(body))
    out += body
    return bytes(out)


def _row(side_fields):
    out = bytearray()
    for column, spec in side_fields:
        if isinstance(spec, str):
            kind, value = spec, None
        elif isinstance(spec, tuple):
            kind = spec[0]
            value = spec[1] if len(spec) > 1 else None
        else:
            raise ValueError("invalid field spec %r for %s" % (spec, column))
        out += field_bytes(kind, value)
    return bytes(out)


def operation_bytes(seq, op, old=None, new=None):
    """Encode one operation. Fields are (kind[, value]) per column."""
    if op not in OPCODES:
        raise ValueError("unknown op %r" % (op,))
    out = bytearray((OPCODES[op],))
    columns = ("id", "tag", "payload")
    if op == "insert":
        out += _row([(c, new[c]) for c in columns])
    elif op == "delete":
        out += _row([(c, old[c]) for c in columns])
    else:
        out += _row([(c, old[c]) for c in columns])
        out += _row([(c, new[c]) for c in columns])
    return bytes(out)


def package_bytes(operations, terminator=b"\x00", suffix=b""):
    """Full package for an iterable of (op, old, new) triples."""
    out = bytearray(MAGIC)
    for seq, (op, old, new) in enumerate(operations):
        out += operation_bytes(seq, op, old=old, new=new)
    out += terminator
    out += suffix
    return bytes(out)


def split_chunks(data, size):
    """Deterministic fixed-size byte splitter (size >= 1)."""
    if size < 1:
        raise ValueError("chunk size must be >= 1")
    return [data[i:i + size] for i in range(0, len(data), size)]
