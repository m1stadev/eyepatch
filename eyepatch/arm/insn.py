from sys import version_info

from capstone import ARM_GRP_JUMP, ARM_OP_IMM

import eyepatch.arm
import eyepatch.base

if version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class Insn(eyepatch.base._Insn, eyepatch.arm._XrefMixin):
    def follow_call(self) -> Self:
        if self.data.group(ARM_GRP_JUMP):
            op = self.data.operands[-1]
            if op.type == ARM_OP_IMM:
                return next(self.disasm.disasm(op.imm + self.offset))

        # TODO: raise error
