from capstone import CS_ARCH_ARM64, CS_MODE_ARM, Cs

import eyepatch.aarch64
import eyepatch.base


class Disassembler(eyepatch.base._Disassembler):
    _insn = eyepatch.aarch64.Insn
    _string = eyepatch.aarch64.ByteString

    def __init__(self, data: bytes):
        # TODO: Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        super().__init__(data=data, disasm=Cs(CS_ARCH_ARM64, CS_MODE_ARM))
