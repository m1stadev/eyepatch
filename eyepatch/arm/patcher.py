from capstone import CS_ARCH_ARM, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, CS_MODE_THUMB, Cs
from keystone import KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB, Ks

import eyepatch.arm


class Patcher(eyepatch.arm.Assembler, eyepatch.arm.Disassembler):
    def __init__(self, data: bytes):
        self._data = data

        self._asm = Ks(KS_ARCH_ARM, KS_MODE_ARM)
        self._disasm = Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        self._disasm.detail = True

        self._thumb_asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)
        self._thumb_disasm = Cs(CS_ARCH_ARM, CS_MODE_THUMB + CS_MODE_LITTLE_ENDIAN)
        self._thumb_disasm.detail = True
