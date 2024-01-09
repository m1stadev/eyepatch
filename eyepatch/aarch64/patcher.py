from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

import eyepatch.aarch64


class Patcher(eyepatch.aarch64.Assembler, eyepatch.aarch64.Disassembler):
    def __init__(self, data: bytes):
        self._data = data

        self._asm = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self._disasm = Cs(CS_ARCH_ARM64, CS_MODE_ARM)
        self._disasm.detail = True
