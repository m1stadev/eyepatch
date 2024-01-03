from typing import Generator, Optional, Union

from capstone import CS_ARCH_ARM64, CS_MODE_ARM, CS_MODE_LITTLE_ENDIAN, Cs, CsError
from keystone import KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN, Ks

from .insn import Insn
from .string import ByteString


class Patcher:
    def __init__(self, data: bytes):
        self._data = data

        # Change arch to CS_ARCH_AARCH64 when Capstone 6.0 releases
        self._cs = Cs(CS_ARCH_ARM64, CS_MODE_ARM + CS_MODE_LITTLE_ENDIAN)
        self._cs.detail = True

        self._ks = Ks(KS_ARCH_ARM64, KS_MODE_LITTLE_ENDIAN)

    def disasm(self, offset: int, reverse: bool = False) -> Generator[Insn, None, None]:
        if reverse:
            len_check = offset - 4 > 0
            range_obj = range(offset, 0, -4)
        else:
            len_check = offset + 4 < len(self._data)
            range_obj = range(offset, len(self._data), 4)

        if not len_check:
            return  # TODO: Raise error

        for i in range_obj:
            if reverse:
                i -= 4

            data = self._data[i : i + 4]

            try:
                instr = next(self._cs.disasm(code=data, offset=0))
                yield Insn(data, i, instr)
            except (CsError, StopIteration):
                pass

    @property
    def data(self) -> bytes:
        return self._data

    def search_instr(
        self, instr: str, skip: int = 0, offset: int = 0
    ) -> Optional[Insn]:
        print(f'searching for {instr} insn (skip={skip}, offset=0x{offset:x})')
        for insn in self.disasm(offset):
            if insn.disasm.mnemonic == instr:
                if skip == 0:
                    # print('found insn:')
                    # print(
                    #    f'0x{insn.offset:x}: {insn.disasm.mnemonic} {insn.disasm.op_str}'
                    # )
                    return insn

                # print('found insn but skipping...')
                skip -= 1

    def search_string(self, string: Union[str, bytes]) -> Optional[ByteString]:
        if isinstance(string, str):
            string = string.encode()

        print(f'searching for string {string.decode()}')
        index = self._data.find(string)
        if index == -1:
            return None
        return ByteString(string, index)
