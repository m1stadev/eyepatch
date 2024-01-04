from typing import Generator, Optional, Union

from capstone import Cs, CsError

from .insn import _Insn
from .string import _ByteString


class _Disassembler:
    _insn = _Insn
    _string = _ByteString

    def __init__(self, disasm: Cs):
        self._disasm = disasm
        self._disasm.detail = True

    def disasm(
        self, offset: int, reverse: bool = False
    ) -> Generator[_insn, None, None]:
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
                instr = next(self._disasm.disasm(code=data, offset=0))
                yield self._insn(self, instr, i)
            except (CsError, StopIteration):
                pass

    @property
    def data(self) -> bytes:
        return self._data

    def search_insn(
        self,
        insn: str,
        offset: int = 0,
        skip: int = 0,
    ) -> Optional[_insn]:
        for insn in self.disasm(offset):
            print(insn)
            if insn.data.mnemonic == insn:
                if skip == 0:
                    return insn

                skip -= 1

    def search_string(self, string: Union[str, bytes]) -> Optional[_string]:
        if isinstance(string, str):
            string = string.encode()

        index = self._data.find(string)
        if index == -1:
            return None

        return self._string(string, index)
