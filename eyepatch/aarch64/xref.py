from typing import Optional

from capstone import ARM64_OP_IMM

import eyepatch.aarch64


class _XrefMixin:
    def xref(self, skip: int = 0) -> Optional[eyepatch.aarch64.Insn]:  # noqa: F821
        for insn in self.patcher.disasm(0x0):
            op = insn.data.operands[-1]
            if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == self.offset:
                if skip == 0:
                    return insn

                skip -= 1
