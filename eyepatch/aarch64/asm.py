from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

import eyepatch.base


class Assembler(eyepatch.base._Assembler):
    def __init__(self):
        super().__init__(asm=Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN))
