from typing import Optional

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from capstone.arm64_const import (
    ARM64_GRP_JUMP,
    ARM64_INS_ADD,
    ARM64_INS_STP,
    ARM64_INS_SUB,
    ARM64_OP_IMM,
    ARM64_REG_SP,
    ARM64_REG_X29,
)

from .base.disasm import _Disassembler
from .base.insn import _Insn
from .base.string import _ByteString


class XrefMixin:
    def xref(self, patcher: 'Disassembler', skip: int = 0) -> Optional['Insn']:  # noqa: F821
        for insn in patcher.disasm(0x0):
            for op in insn.data.operands:
                if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == self.offset:
                    if skip == 0:
                        return insn

                    skip -= 1


class Insn(_Insn, XrefMixin):
    def follow_call(self) -> 'Insn':  # noqa: F821
        if self._disasm.disasm.group(ARM64_GRP_JUMP):
            for op in self.disasm.operands:
                if op.type == ARM64_OP_IMM:
                    return next(self._disasm.disasm(op.imm + self.offset))

        # TODO: raise error

    def function_begin(self) -> 'Insn':  # noqa: F821
        disasm = self._disasm.disasm(self.offset, reverse=True)
        while True:
            insn = next(disasm)
            if (insn.data.id != ARM64_INS_ADD) and (
                [op.reg for op in insn.data.operands[:2]]
                != [ARM64_REG_X29, ARM64_REG_SP]
            ):
                continue

            if (insn := next(disasm)).data.id != ARM64_INS_STP:
                continue

            while insn.data.id in (ARM64_INS_STP, ARM64_INS_SUB):
                insn = next(disasm)

            return next(self._disasm.disasm(insn.offset + 4))


class ByteString(_ByteString, XrefMixin):
    pass


class Disassembler(_Disassembler):
    _insn = Insn
    _string = ByteString

    def __init__(self, data: bytes):
        # TODO: Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        super().__init__(disasm=Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN))

        self._data = data
