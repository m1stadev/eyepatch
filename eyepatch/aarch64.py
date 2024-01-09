from sys import version_info
from typing import Optional

from capstone import (
    CS_ARCH_ARM64,
    CS_MODE_ARM,
    Cs,
)
from capstone.arm64_const import (
    ARM64_GRP_JUMP,
    ARM64_INS_ADD,
    ARM64_INS_STP,
    ARM64_INS_SUB,
    ARM64_OP_IMM,
    ARM64_REG_SP,
    ARM64_REG_X29,
)
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

import eyepatch.base

if version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class _XrefMixin:
    def xref(self, skip: int = 0) -> Optional['Insn']:  # noqa: F821
        for insn in self.patcher.disasm(0x0):
            op = insn.info.operands[-1]
            if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == self.offset:
                if skip == 0:
                    return insn

                skip -= 1


class ByteString(eyepatch.base._ByteString, _XrefMixin):
    pass


class Insn(eyepatch.base._Insn, _XrefMixin):
    def follow_call(self) -> Self:
        if self.info.group(ARM64_GRP_JUMP):
            op = self.info.operands[-1]
            if op.type == ARM64_OP_IMM:
                return next(self.patcher.disasm(op.imm + self.offset))

        # TODO: raise error

    def function_begin(self) -> Self:
        disasm = self.disasm.disasm(self.offset, reverse=True)
        while True:
            insn = next(disasm)
            if (insn.info.id != ARM64_INS_ADD) and (
                [op.reg for op in insn.info.operands[:2]]
                != [ARM64_REG_X29, ARM64_REG_SP]
            ):
                continue

            if (insn := next(disasm)).info.id != ARM64_INS_STP:
                continue

            while insn.info.id in (ARM64_INS_STP, ARM64_INS_SUB):
                insn = next(disasm)

            return next(self.disasm.disasm(insn.offset + 4))


class _Assembler(eyepatch.base._Assembler):
    def __init__(self):
        super().__init__(asm=Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN))


class _Disassembler(eyepatch.base._Disassembler):
    _insn = Insn
    _string = ByteString

    def __init__(self, data: bytes):
        # TODO: Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        super().__init__(data=data, disasm=Cs(CS_ARCH_ARM64, CS_MODE_ARM))


class Patcher(_Assembler, _Disassembler):
    def __init__(self, data: bytes):
        self._data = data

        self._asm = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self._disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self._disasm.detail = True
