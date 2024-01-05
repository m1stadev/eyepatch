from keystone import Ks, KsError


class _Assembler:
    def __init__(self, asm: Ks):
        self._asm = asm

    def asm(self, insn: str) -> bytes:
        try:
            asm, _ = self._asm.asm(insn, as_bytes=True)
        except KsError:
            # TODO: Raise error
            pass

        return asm
