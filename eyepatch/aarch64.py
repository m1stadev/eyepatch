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


class ByteString(eyepatch.base._ByteString):
    pass


class Insn(eyepatch.base._Insn):
    def follow_call(self) -> Self:
        if self.info.group(ARM64_GRP_JUMP):
            op = self.info.operands[-1]
            if op.type == ARM64_OP_IMM:
                return next(self.patcher.disasm(op.imm + self.offset))

        # TODO: raise error

    def function_begin(self) -> Self:
        disasm = self.patcher.disasm(self.offset, reverse=True)
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

            return next(self.patcher.disasm(insn.offset + 4))


class Patcher(eyepatch.base._Patcher):
    _insn = Insn
    _string = ByteString

    def __init__(self, data: bytes):
        # TODO: Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        super().__init__(
            data=data,
            asm=Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN),
            disasm=Cs(CS_ARCH_ARM64, CS_MODE_ARM),
        )

    def search_xref(self, offset: int, skip: int = 0) -> Optional[_insn]:  # noqa: F821
        for insn in self.disasm(0x0):
            if len(insn.info.operands) == 0:
                continue

            op = insn.info.operands[-1]
            if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == offset:
                if skip == 0:
                    return insn

                skip -= 1
