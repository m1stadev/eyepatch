from typing import Optional

from capstone.arm64_const import ARM64_OP_IMM


class ByteString:
    def __init__(self, string: bytes, offset: int):
        self._str = string
        self._offset = offset

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: {self._str.decode()}'

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def offset(self) -> int:
        return self._offset

    def xref(self, patcher: 'Patcher', skip: int = 0) -> Optional['Insn']:  # noqa: F821
        for insn in patcher.disasm(0x0):
            for op in insn.disasm.operands:
                if op.type == ARM64_OP_IMM and (op.imm + insn.offset) == self.offset:
                    if skip == 0:
                        return insn
                    skip -= 1
