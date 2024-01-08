from sys import version_info
from typing import Optional

from capstone import CsInsn

import eyepatch.base

if version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class _Insn:
    def __init__(
        self,
        offset: int,
        data: bytes,
        info: Optional[CsInsn] = None,
        patcher: Optional[eyepatch.base._Patcher] = None,
    ):
        self._offset = offset
        self._data = data

        self._info = info
        self._patcher = patcher

    def __next__(self) -> Self:
        return next(self.disasm.disasm(self.offset + 0x4))

    def __repr__(self) -> str:
        if self.info is not None:
            insn = f'{self.info.mnemonic} {self.info.op_str}'
            return f'0x{self.offset:x}: {self.info.mnemonic} {self.info.op_str}'
        else:
            insn = self.data.hex()

        return f'0x{self.offset:x}: {insn}'

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def patcher(self) -> eyepatch.base._Patcher:
        return self._patcher

    def patch(self, insn: str) -> None:
        data = self.patcher.asm(insn)
        if len(data) != len(data):
            raise ValueError(
                'New instruction must be the same size as the current instruction'
            )

        self._data = data
        self.patcher._data[self.offset : self.offset + len(data)] = data
        self._info = self.disasm._disasm(code=data, offset=0)
