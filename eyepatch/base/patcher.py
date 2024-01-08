from capstone import Cs
from keystone import Ks

import eyepatch.base


class _Patcher(eyepatch.base._Assembler, eyepatch.base._Disassembler):
    def __init__(self, data: bytes, asm: Ks, disasm: Cs):
        self._data = data

        self._asm = asm
        self._disasm = disasm
        self._disasm.detail = True
