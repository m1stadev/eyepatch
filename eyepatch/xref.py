from typing import Optional

from capstone.arm64_const import ARM64_OP_IMM


class XrefMixin:
    def xref(self, patcher: 'Patcher', skip: int = 0) -> Optional['Insn']:  # noqa: F821
        for insn in patcher.disasm(0x0):
            for op in insn.disasm.operands:
                if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == self.offset:
                    if skip == 0:
                        return insn
                    skip -= 1
