from capstone import CsInsn
from capstone.arm64_const import (
    ARM64_GRP_JUMP,
    ARM64_INS_ADD,
    ARM64_INS_STP,
    ARM64_OP_IMM,
    ARM64_REG_SP,
    ARM64_REG_X29,
)

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

    def function_begin(self, patcher: 'Patcher') -> 'Insn':  # noqa: F821
        disasm = patcher.disasm(self.offset, reverse=True)
        while True:
            insn = next(disasm)
            if (insn.disasm.id != ARM64_INS_ADD) and (
                [op.reg for op in insn.disasm.operands[:2]]
                != [ARM64_REG_X29, ARM64_REG_SP]
            ):
                continue
            if (insn := next(disasm)).disasm.id != ARM64_INS_STP:
                continue

            while insn.disasm.id == ARM64_INS_STP:
                insn = next(disasm)

            return insn
