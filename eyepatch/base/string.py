class _ByteString:
    def __init__(self, string: bytes, offset: int):
        self._str = string
        self._offset = offset

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self._str.decode()}'

    @property
    def string(self) -> bytes:
        return self._str

    @property
    def offset(self) -> int:
        return self._offset
