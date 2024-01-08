from capstone import CsInsn


class _Insn:
    def __init__(self, disasm: '_Disassembler', data: CsInsn, offset: int):  # noqa: F821
        self._disasm = disasm
        self._data = data
        self._offset = offset

    def __next__(self) -> '_Insn':  # noqa: F821
        return next(self.disasm.disasm(self.offset + 0x4))

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self.data.mnemonic} {self.data.op_str}'

    @property
    def data(self) -> CsInsn:
        return self._data

    @property
    def disasm(self) -> '_Disassembler':  # noqa: F821
        return self._disasm

    @property
    def offset(self) -> int:
        return self._offset

    def patch(self, data: bytes) -> '_Insn':
        if len(data) != self.data.size:
            raise ValueError(
                'New instruction must be the same size as the current instruction'
            )

        self.disasm._data[self.offset : self.offset + len(data)] = data
        insn = self.disasm._disasm(code=data, offset=0)
        return self.__class__(self, insn, self.offset)
