from struct import unpack
from sys import version_info
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
from keystone import KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB, Ks, KsError

import eyepatch
import eyepatch.base

if version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class ByteString(eyepatch.base._ByteString):
    pass


class Insn(eyepatch.base._Insn):
    def follow_call(self) -> Self:
        if self.info.group(ARM_GRP_JUMP):
            op = self.info.operands[-1]
            if op.type == ARM_OP_IMM:
                return next(self.patcher.disasm(op.imm + self.offset))

        raise eyepatch.InsnError('Instruction is not a call')

    def patch(self, insn: str) -> None:
        if self.info._cs.mode & CS_MODE_THUMB:
            data = self.patcher.asm_thumb(insn)
        else:
            data = self.patcher.asm(insn)

        if len(data) != len(self.data):
            raise ValueError(
                'New instruction must be the same size as the current instruction'
            )

        self._data = bytearray(data)
        self.patcher._data[self.offset : self.offset + len(data)] = data
        self._info = self.patcher.disasm(self.offset)


class Patcher(eyepatch.base._Patcher):
    _insn = Insn
    _string = ByteString

    def __init__(self, data: bytes):
        super().__init__(
            data=data,
            asm=Ks(KS_ARCH_ARM, KS_MODE_ARM),
            disasm=Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN),
        )

        self._thumb_asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self._thumb_disasm = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        self._thumb_disasm.detail = True

    def asm_thumb(self, insn: str) -> bytes:
        try:
            asm, _ = self._thumb_asm.asm(insn, as_bytes=True)
        except KsError:
            raise eyepatch.AssemblyError(
                f'Failed to assemble ARM thumb instruction: {insn}'
            )

        return asm

    def disasm(
        self, offset: int, reverse: bool = False
    ) -> Generator[_insn, None, None]:
        if reverse:
            loop = offset > 0
        else:
            loop = offset < len(self._data)

        while loop:
            # disassemble as 16-bit thumb insn
            if reverse:
                if (offset - 2) == 0:
                    raise ValueError('Offset is outside of data range')

                data = self._data[offset - 2 : offset]

            else:
                if (offset + 2) > len(self._data):
                    raise ValueError('Offset is outside of data range')

                data = self._data[offset : offset + 2]

            try:
                insn = next(self._thumb_disasm.disasm(code=data, offset=0))

                if reverse:
                    offset -= 2

                yield self._insn(offset, data, insn, self)

                if not reverse:
                    offset += 2

                continue

            except (CsError, StopIteration):
                pass

            # disassemble as 32-bit thumb insn
            if reverse:
                if (offset - 4) == 0:
                    raise ValueError('Offset is outside of data range')

                data = self._data[offset - 4 : offset]

            else:
                if (offset + 4) > len(self._data):
                    raise ValueError('Offset is outside of data range')

                data = self._data[offset : offset + 4]

            try:
                insn = next(self._thumb_disasm.disasm(code=data, offset=0))

                if reverse:
                    offset -= 4

                yield self._insn(offset, data, insn, self)

                if not reverse:
                    offset += 4

                continue

            except (CsError, StopIteration):
                pass

            # disassemble as 32-bit arm insn
            try:
                insn = next(self._disasm.disasm(code=data, offset=0))

                if reverse:
                    offset -= 4

                yield self._insn(offset, data, insn, self)

                if not reverse:
                    offset += 4

                continue

            except (CsError, StopIteration):
                pass

            # all else fails, just increment offset by 2
            offset += 2

    def search_imm(self, imm: int, offset: int = 0, skip: int = 0) -> _insn:
        for insn in self.disasm(offset):
            if len(insn.info.operands) == 0:
                continue

            op = insn.info.operands[-1]
            if op.type == ARM_OP_MEM:
                if op.mem.base != ARM_REG_PC:
                    continue

                imm_offset = (insn.offset & ~3) + op.mem.disp + 0x4
                data = self.data[imm_offset : imm_offset + 4]
                insn_imm = unpack('<i', data)[0]

                if insn_imm == imm:
                    if skip == 0:
                        return insn

                    skip -= 1

            elif op.type == ARM_OP_IMM:
                if op.imm == imm:
                    if skip == 0:
                        return insn

                    skip -= 1
        else:
            raise eyepatch.SearchError(
                f'Failed to find instruction with immediate value: {hex(imm)}'
            )

    def search_thumb_insns(self, *insns: str) -> Insn:
        instructions = '\n'.join(insns)
        data = self.asm_thumb(instructions)
        offset = self.data.find(data)
        if offset == -1:
            raise eyepatch.SearchError(f'Failed to find instructions: {instructions}')

        return next(self.disasm(offset))

    def search_xref(
        self, offset: int, base_addr: int, skip: int = 0
    ) -> Optional['Insn']:
        for insn in self.disasm(0x0):
            if len(insn.info.operands) == 0:
                continue

            op = insn.info.operands[-1]
            if op.type == ARM_OP_MEM:
                if op.mem.base != ARM_REG_PC:
                    continue

                insn_offset = (insn.offset & ~3) + op.mem.disp + 0x4

                data = self.data[insn_offset : insn_offset + 4]
                offset2 = unpack('<i', data)[0]

                if offset2 - offset == base_addr:
                    if skip == 0:
                        return insn

                    skip -= 1

            elif op.type == ARM_OP_IMM:
                if op.imm + insn.offset == offset:
                    if skip == 0:
                        return insn

                    skip -= 1

        raise eyepatch.SearchError(f'Failed to find xrefs to offset: 0x{offset:x}')
