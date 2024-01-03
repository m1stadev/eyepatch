from typing import Optional

from capstone import CsInsn
from capstone.arm64_const import ARM64_OP_IMM


class Insn:
    def __init__(self, patcher: 'Patcher', data: bytes, offset: int, disasm):  # noqa: F821
        self._patcher = patcher
        self._data = data
        self._offset = offset
        self._disasm = disasm

    def __next__(self) -> 'Insn':
        return Insn(next(self.patcher.disasm(self.offset + 4)))

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self.disasm.mnemonic} {self.disasm.op_str}'

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def disasm(self) -> CsInsn:
        return self._disasm

    @property
    def offset(self) -> int:
        return self._offset

    def xref(self, skip: int = 0) -> Optional['Insn']:
        for insn in self._patcher.disasm(0):
            for op in insn.disasm.operands:
                if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == self.offset:
                    if skip == 0:
                        return insn
                    skip -= 1
