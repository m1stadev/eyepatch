from struct import unpack
from typing import Generator, Optional

from capstone import (
    ARM_OP_IMM,
    ARM_OP_MEM,
    ARM_REG_PC,
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
    CsError,
)

import eyepatch.arm
import eyepatch.base


class Disassembler(eyepatch.base._Disassembler):
    _insn = eyepatch.arm.Insn
    _string = eyepatch.arm.ByteString

    def __init__(self, data: bytes):
        super().__init__(
            data=data, disasm=Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        )

        self._thumb_disasm = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        self._thumb_disasm.detail = True

    def disasm(
        self, offset: int, reverse: bool = False
    ) -> Generator[_insn, None, None]:
        if reverse:
            len_check = offset - 2 > 0
            range_obj = range(offset, 0, -2)
        else:
            len_check = offset + 2 < len(self._data)
            range_obj = range(offset, len(self._data), 2)

        if not len_check:
            return  # TODO: Raise error

        for i in range_obj:
            if reverse:
                i -= 4

            # ugly code but it works(-ish)
            # try in the following order:
            # disassemble 2 bytes as thumb insn
            # disassemble 4 bytes as thumb insn
            # disassemble 4 bytes as arm insn
            insn = None
            for size in (2, 4):
                data = self._data[i : i + size]

                try:
                    insn = next(self._thumb_disasm.disasm(code=data, offset=0))
                    break
                except (CsError, StopIteration):
                    if size == 4:
                        try:
                            insn = next(self._disasm.disasm(code=data, offset=0))
                            break
                        except (CsError, StopIteration):
                            pass

            if insn is not None:
                yield self._insn(self, insn, i)

    def search_imm(self, imm: int, offset: int = 0, skip: int = 0) -> Optional[_insn]:
        match = None
        for insn in self.disasm(offset):
            if len(insn.data.operands) == 0:
                continue

            op = insn.data.operands[-1]
            if op.type == ARM_OP_MEM:
                if op.mem.base != ARM_REG_PC:
                    continue

                imm_offset = (insn.offset & ~3) + op.mem.disp + 0x4
                data = self.data[imm_offset : imm_offset + 4]
                insn_imm = unpack('<i', data)[0]

                if insn_imm == imm:
                    if skip == 0:
                        match = insn
                        break

                    skip -= 1

            elif op.type == ARM_OP_IMM:
                if op.imm == imm:
                    if skip == 0:
                        match = insn
                        break

                    skip -= 1

        return match
