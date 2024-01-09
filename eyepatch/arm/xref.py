from struct import unpack
from typing import Optional

from capstone import ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

import eyepatch.arm


class _XrefMixin:
    def xref(self, base_addr: int, skip: int = 0) -> Optional[eyepatch.arm.Insn]:
        xref_insn = None
        for insn in self.disasm.disasm(0x0):
            # TODO: add support for other instructions
            if len(insn.data.operands) == 0:
                continue

            op = insn.data.operands[-1]
            if op.type == ARM_OP_MEM:
                if op.mem.base != ARM_REG_PC:
                    continue

                offset = (insn.offset & ~3) + op.mem.disp + 0x4

                data = self.disasm.data[offset : offset + 4]
                offset2 = unpack('<i', data)[0]

                if offset2 - self.offset == base_addr:
                    if skip == 0:
                        xref_insn = insn
                        break

                    skip -= 1

            elif op.type == ARM_OP_IMM:
                if op.imm + insn.offset == self.offset:
                    if skip == 0:
                        xref_insn = insn
                        break

                    skip -= 1

        return xref_insn
