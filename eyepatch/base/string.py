class _ByteString:
    def __init__(self, disasm: '_Disassembler', data: bytes, offset: int):  # noqa: F821
        self._disasm = disasm
        self._data = data
        self._offset = offset

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self.string}'

    @property
    def disasm(self) -> '_Disassembler':  # noqa: F821
        return self._disasm

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def string(self) -> str:
        return self._data.decode()

    @property
    def offset(self) -> int:
        return self._offset
