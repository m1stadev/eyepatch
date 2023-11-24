from typing import Optional

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

from .types import Insn


class Patcher:
    def __init__(self, data: bytes):
        self.data = data
        # Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        self._cs.detail = True
        self._cs.skipdata = True

        self._ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)
        self._insns = self._disasm_data()

    def __len__(self):
        return len(self.data)

    def _disasm_data(self) -> list[Insn]:
        insns = []
        for i in range(0, len(self.data), 4):
            insn = self._disasm(self.data[i : i + 4])
            if insn == -1:
                pass

            elif insn is not None:
                insns.append(insn)
            else:  # TODO: string parsing
                pass

        self._insns = insns

    def _disasm(self, data: bytes) -> Optional[Insn]:
        if len(data) != 4:
            raise ValueError('data must be 4 bytes')

        try:
            insn = next(insn for insn in self._cs.disasm(data, 0, 1))
        except StopIteration:
            return -1

        if insn.insn_name() == 'udf':
            return None
        else:
            return Insn(insn.mnemonic, insn.op_str, insn.bytes)

    @property
    def data(self) -> bytes:
        return self._data

    @data.setter
    def data(self, data: bytes):
        if not isinstance(data, bytes):
            raise TypeError('data must be of type bytes')

        self._data = data
