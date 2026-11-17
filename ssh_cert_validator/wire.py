"""SSH wire-format primitives used by OpenSSH certificates.

Only the small subset of RFC 4251 needed to parse certificate blobs is
implemented.  All multi-byte integers are big-endian and every length-prefixed
blob is framed by a uint32 byte count.
"""

from __future__ import annotations


class WireError(ValueError):
    """Raised when a blob is truncated, malformed or has trailing bytes."""


class WireReader:
    """Sequential reader for SSH encoded strings and integers."""

    def __init__(self, blob: bytes) -> None:
        self.blob = bytes(blob)
        self.pos = 0

    def remaining(self) -> int:
        return len(self.blob) - self.pos

    def take(self, count: int) -> bytes:
        if count < 0:
            raise WireError("negative read length")
        if self.pos + count > len(self.blob):
            raise WireError(
                "truncated blob: need %d bytes at offset %d, have %d"
                % (count, self.pos, self.remaining())
            )
        chunk = self.blob[self.pos:self.pos + count]
        self.pos += count
        return chunk

    def u32(self) -> int:
        return int.from_bytes(self.take(4), "big")

    def u64(self) -> int:
        return int.from_bytes(self.take(8), "big")

    def string(self) -> bytes:
        length = self.u32()
        return self.take(length)

    def expect_end(self) -> None:
        if self.pos != len(self.blob):
            raise WireError(
                "unexpected trailing bytes: %d byte(s) left at offset %d"
                % (self.remaining(), self.pos)
            )


def encode_string(value: bytes) -> bytes:
    """Frame ``value`` with its uint32 length prefix."""
    if len(value) > 0xFFFFFFFF:
        raise WireError("string too long for uint32 length prefix")
    return len(value).to_bytes(4, "big") + value


def encode_u32(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFF:
        raise WireError("uint32 out of range: %r" % (value,))
    return value.to_bytes(4, "big")


def encode_u64(value: int) -> bytes:
    if not 0 <= value <= 0xFFFFFFFFFFFFFFFF:
        raise WireError("uint64 out of range: %r" % (value,))
    return value.to_bytes(8, "big")


def read_packed_strings(container: bytes) -> list[bytes]:
    """Parse a nested SSH string that packs a sequence of length-prefixed
    strings without a separate count (the ``valid principals`` layout)."""
    reader = WireReader(container)
    entries: list[bytes] = []
    while reader.remaining():
        entries.append(reader.string())
    return entries


def read_packed_pairs(container: bytes) -> list[tuple[bytes, bytes]]:
    """Parse a nested SSH string packing concatenated name/data string pairs
    (the ``critical options`` and ``extensions`` layout)."""
    reader = WireReader(container)
    pairs: list[tuple[bytes, bytes]] = []
    while reader.remaining():
        pairs.append((reader.string(), reader.string()))
    reader.expect_end()
    return pairs
