from capstone import CsInsn
from capstone.arm64_const import ARM64_GRP_JUMP, ARM64_OP_IMM

from .xref import XrefMixin


class Insn(XrefMixin):
    def __init__(self, data: bytes, offset: int, disasm):  # noqa: F821
        self._data = data
        self._offset = offset
        self._disasm = disasm

    def __next__(self) -> 'Insn':
        return Insn(next(self.patcher.disasm(self.offset + 4)))

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self.disasm.mnemonic} {self.disasm.op_str}'

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def disasm(self) -> CsInsn:
        return self._disasm

    @property
    def offset(self) -> int:
        return self._offset

    def follow_call(self, patcher: 'Patcher') -> 'Insn':  # noqa: F821
        if self.disasm.group(ARM64_GRP_JUMP):
            for op in self.disasm.operands:
                if op.type == ARM64_OP_IMM:
                    return next(patcher.disasm(op.imm + self.offset))

        # TODO: raise error
