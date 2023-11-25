from typing import Optional

from binary2strings import extract_all_strings
from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

from .types import Insn, String


class Patcher:
    def __init__(self, data: bytes):
        self.data = data

        # Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        # TODO: We can probably use diet engine instead to save memory/time
        self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        self._ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

        self._disasm_data()

    def __len__(self):
        return len(self.data)

    def _disasm_data(self) -> list[Insn]:
        self._strings = [
            String(string[0], string[2][0], len(string[0]))
            for string in extract_all_strings(self.data, only_interesting=True)
        ]

        string_offsets = set()
        for string in self._strings:
            string_offsets.update(range(string.offset, string.offset + string.length))

        self._insns = []
        for i in range(0, len(self.data), 4):
            if i in string_offsets:
                continue

            insn = self._disasm(self.data[i : i + 4])
            if insn is not None:
                self._insns.append(insn)
            else:  # TODO: string parsing
                pass

    def _disasm(self, data: bytes) -> Optional[Insn]:
        if len(data) != 4:
            raise ValueError('data must be 4 bytes')

        try:
            insn = next(insn for insn in self._cs.disasm(data, 0, 1))
        except StopIteration:
            return None

        if insn.insn_name() == 'udf':
            return None
        else:
            return Insn(insn.mnemonic, insn.op_str, insn.bytes)

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def insns(self) -> list[Insn]:
        return self._insns

    @property
    def strings(self) -> list[String]:
        return self._strings
