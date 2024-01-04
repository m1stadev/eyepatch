from capstone import Cs, CsInsn


class _Insn:
    def __init__(self, disasm: '_Disassembler', data: CsInsn, offset: int):  # noqa: F821
        self._disasm = disasm
        self._data = data
        self._offset = offset

    def __next__(self) -> '_Insn':  # noqa: F821
        return self.__class__(next(self._disasm.disasm(self.offset + 4)))

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self.data.mnemonic} {self.data.op_str}'

    @property
    def data(self) -> CsInsn:
        return self._data

    @property
    def disasm(self) -> Cs:
        return self._disasm

    @property
    def offset(self) -> int:
        return self._offset
