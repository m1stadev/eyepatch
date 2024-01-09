from keystone import KS_ARCH_ARM, KS_MODE_ARM, KS_MODE_THUMB, Ks, KsError

import eyepatch.base


class Assembler(eyepatch.base._Assembler):
    def __init__(self):
        super().__init__(asm=Ks(KS_ARCH_ARM, KS_MODE_ARM))

        self._thumb_asm = Ks(KS_ARCH_ARM, KS_MODE_THUMB)

    def asm_thumb(self, insn: str) -> bytes:
        try:
            asm, _ = self._thumb_asm.asm(insn, as_bytes=True)
        except KsError:
            # TODO: Raise error
            pass

        return asm
