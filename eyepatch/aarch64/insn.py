from sys import version_info

from capstone import (
    ARM64_GRP_JUMP,
    ARM64_INS_ADD,
    ARM64_INS_STP,
    ARM64_INS_SUB,
    ARM64_OP_IMM,
    ARM64_REG_SP,
    ARM64_REG_X29,
)

import eyepatch.aarch64
import eyepatch.base

if version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class Insn(eyepatch.base._Insn, eyepatch.aarch64._XrefMixin):
    def follow_call(self) -> Self:
        if self.data.group(ARM64_GRP_JUMP):
            op = self.data.operands[-1]
            if op.type == ARM64_OP_IMM:
                return next(self.disasm.disasm(op.imm + self.offset))

        # TODO: raise error

    def function_begin(self) -> Self:
        disasm = self.disasm.disasm(self.offset, reverse=True)
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

            return next(self.disasm.disasm(insn.offset + 4))
