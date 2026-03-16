"""
Memory safety utilities.
Single responsibility: secure cleanup of sensitive buffers.
"""


def zero_bytes(buf: bytearray) -> None:
    """Best-effort 3-pass memory overwrite (0x00, 0xFF, 0x00).

    Matches browser MemoryUtils.overwriteBuffer and CLI cleanup pattern.
    Not guaranteed in Python due to GC and interning, but reduces the
    window where sensitive data is readable in memory.
    """
    for pattern in (0x00, 0xFF, 0x00):
        buf[:] = bytes([pattern]) * len(buf)
