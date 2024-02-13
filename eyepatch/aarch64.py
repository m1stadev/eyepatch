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
    ARM64_SFT_LSL,
)
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

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
        if self.info.group(ARM64_GRP_JUMP):
            op = self.info.operands[-1]
            if op.type == ARM64_OP_IMM:
                return next(self.patcher.disasm(op.imm + self.offset))

        raise eyepatch.InsnError('Instruction is not a call')

    def function_begin(self) -> Self:
        disasm = self.patcher.disasm(self.offset, reverse=True)
        while True:
            try:
                insn = next(disasm)
            except StopIteration:
                raise eyepatch.DisassemblyError('Failed to find beginning of function')

            if insn.info.id != ARM64_INS_ADD:
                continue

            if [op.reg for op in insn.info.operands[:2]] != [
                ARM64_REG_X29,
                ARM64_REG_SP,
            ]:
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
            if insn.info.mnemonic in (
                'b',
                'bl',
                'cbnz',
                'cbz',
                'adr',
                'tbz',
                'tbnz',
                'ldr',
            ):
                op = insn.info.operands[-1]
                if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == offset:
                    if skip == 0:
                        return insn

                    skip -= 1

        raise eyepatch.SearchError(f'Failed to find xrefs to offset: 0x{offset:x}')

    def search_imm(self, imm: int, offset: int = 0, skip: int = 0) -> _insn:
        for insn in self.disasm(offset):
            if len(insn.info.operands) == 0:
                continue

            val = insn.info.operands[-1].imm
            if insn.info.mnemonic == 'mov':
                movk = next(insn)
                while movk.info.mnemonic == 'movk':
                    shift = movk.info.operands[-1].shift
                    if shift.type == ARM64_SFT_LSL:
                        val |= movk.info.operands[-1].imm << shift.value
                    else:
                        val |= movk.info.operands[-1].imm

                    movk = next(movk)

            if val == imm:
                if skip == 0:
                    return insn

                skip -= 1

        raise eyepatch.SearchError(
            f'Failed to find instruction with immediate value: {hex(imm)}'
        )
