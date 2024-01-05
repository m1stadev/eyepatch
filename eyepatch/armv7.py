from struct import unpack
from typing import Generator, Optional

from capstone import (
    CS_ARCH_ARM,
    CS_MODE_ARM,
    CS_MODE_LITTLE_ENDIAN,
    CS_MODE_THUMB,
    Cs,
    CsError,
)
from capstone.arm_const import ARM_GRP_JUMP, ARM_OP_IMM, ARM_OP_MEM, ARM_REG_PC

from .base.disasm import _Disassembler
from .base.insn import _Insn
from .base.string import _ByteString


class XrefMixin:
    def xref(self, skip: int = 0) -> Optional['Insn']:  # noqa: F821
        xref_insn = None
        for insn in self.disasm.disasm(0x0):
            # TODO: add support for other instructions
            if len(insn.data.operands) == 0:
                continue

            op = insn.data.operands[-1]
            if op.type == ARM_OP_MEM:
                if op.mem.base != ARM_REG_PC:
                    continue

                offset = insn.offset + op.mem.disp

                data = self.disasm.data[offset : offset + 4]
                offset2 = unpack('<i', data)[0]

                # TODO: we can't confirm without image base so this is just hardcoded rn, fix later
                if offset2 - self.offset == 0x4FF00000:
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


class Insn(_Insn, XrefMixin):
    def follow_call(self) -> 'Insn':  # noqa: F821
        if self.data.group(ARM_GRP_JUMP):
            for op in self.data.operands:
                if op.type == ARM_OP_IMM:
                    return next(self.disasm.disasm(op.imm + self.offset))

        # TODO: raise error


class ByteString(_ByteString, XrefMixin):
    pass


class Disassembler(_Disassembler):
    _insn = Insn
    _string = ByteString

    def __init__(self, data: bytes):
        super().__init__(disasm=Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN))

        self._thumb_disasm = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        self._thumb_disasm.detail = True

        self._data = data

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
