import ctypes
from ..domain.memory import Memory


class MemoryImpl(Memory):

    def scrub_bytes(self, data: bytearray) -> None:
        ctypes.memset(id(data), 0, len(data))

    def scrub_int(self, value: int) -> None:
        ctypes.memset(id(value), 0, value.bit_length() // 8 + 1)