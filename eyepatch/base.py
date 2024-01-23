from sys import version_info
from typing import Generator, Optional, Union

from capstone import Cs, CsError, CsInsn
from keystone import Ks, KsError

import eyepatch

if version_info >= (3, 11):
    from typing import Self
else:
    from typing_extensions import Self


class _Assembler:
    def __init__(self, asm: Ks):
        self._asm = asm

    def asm(self, insn: str) -> bytes:
        try:
            asm, _ = self._asm.asm(insn, as_bytes=True)
        except KsError:
            raise eyepatch.AssemblyError(f'Failed to assemble instruction: {insn}')

        return asm


class _Insn:
    def __init__(
        self,
        offset: int,
        data: bytes,
        info: CsInsn,
        patcher: '_Patcher',
    ):
        self._offset = offset
        self._data = bytearray(data)
        self._patcher = patcher
        self._info = info

    def __eq__(self, other) -> bool:
        if not isinstance(other, _Insn):
            return False

        return self.data == other.data

    def __next__(self) -> Self:
        return next(self.patcher.disasm(self.offset + 0x4))

    def __repr__(self) -> str:
        if self.info is not None:
            insn = f'{self.info.mnemonic} {self.info.op_str}'
            return f'0x{self.offset:x}: {self.info.mnemonic} {self.info.op_str}'
        else:
            insn = self.data.hex()

        return f'0x{self.offset:x}: {insn}'

    @property
    def info(self) -> CsInsn:
        return self._info

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def patcher(self) -> '_Patcher':
        return self._patcher

    def patch(self, insn: str) -> None:
        data = self.patcher.asm(insn)
        if len(data) != len(self.data):
            raise ValueError(
                'New instruction must be the same size as the current instruction'
            )

        self._data = bytearray(data)
        self.patcher._data[self.offset : self.offset + len(data)] = data
        self._info = self.patcher.disasm(self.offset)


class _ByteString:
    def __init__(self, offset: int, data: bytes, patcher: '_Patcher' = None):
        self._offset = offset
        self._data = bytearray(data)
        self._patcher = patcher

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: "{self.string}"'

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    @property
    def string(self) -> str:
        return self._data.decode()

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def patcher(self) -> '_Patcher':
        return self._patcher

    def replace(
        self,
        oldvalue: Union[str, bytes],
        newvalue: Union[str, bytes],
        count: Optional[int] = None,
    ) -> None:
        if isinstance(oldvalue, str):
            oldvalue = oldvalue.encode()

        if isinstance(newvalue, str):
            newvalue = newvalue.encode()

        if oldvalue not in self._data:
            raise ValueError(f'"{oldvalue}" is not in string.')

        if len(oldvalue) > len(newvalue):
            oldvalue += b' ' * (len(newvalue) - len(oldvalue))

        elif len(oldvalue) < len(newvalue):
            raise ValueError("New value can't be longer than old value.")

        self._data = self._data.replace(oldvalue, newvalue, count)
        self.patcher._data[self.offset : self.offset + len(self._data)] = self._data


class _Disassembler:
    _insn = _Insn
    _string = _ByteString

    def __init__(self, data: bytes, disasm: Cs):
        self._data = bytearray(data)
        self._disasm = disasm
        self._disasm.detail = True

    @property
    def data(self) -> bytes:
        return bytes(self._data)

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
            raise ValueError('Offset is outside of data range')

        for i in range_obj:
            if reverse:
                i -= 4

            data = self._data[i : i + 4]

            try:
                insn = next(self._disasm.disasm(code=data, offset=0))
                yield self._insn(i, data, insn, self)
            except (CsError, StopIteration):
                pass

    def search_insn(
        self, insn_name: str, offset: int = 0, skip: int = 0, reverse: bool = False
    ) -> Optional[_insn]:
        for insn in self.disasm(offset, reverse):
            if insn.info.mnemonic == insn_name:
                if skip == 0:
                    return insn

                skip -= 1

        raise eyepatch.SearchError(f'Failed to find instruction: {insn_name}')

    def search_imm(self, imm: int, offset: int = 0, skip: int = 0) -> _insn:
        for insn in self.disasm(offset):
            if any(imm == op.imm for op in insn.info.operands):
                if skip == 0:
                    return insn

                skip -= 1

        raise eyepatch.SearchError(
            f'Failed to find instruction with immediate value: {hex(imm)}'
        )

    def search_string(
        self,
        string: Optional[Union[str, bytes]] = None,
        offset: Optional[int] = None,
        skip: int = 0,
        exact: bool = False,
    ) -> _string:
        if string is not None:
            if isinstance(string, str):
                string = string.encode()

            if exact:
                str_begin = self._data.find(b'\0' + string + b'\0') + 1
                if str_begin == 0:
                    raise eyepatch.SearchError(f'Failed to find string: {string}')

                str_end = str_begin + len(string)
            else:
                part_str = self._data.find(string)
                while skip > 0:
                    part_str = self._data.find(string, part_str + 1)
                    skip -= 1

                if part_str == -1:
                    raise eyepatch.SearchError(f'Failed to find string: {string}')

                str_begin = self.data.rfind(b'\0', 0, part_str) + 1
                str_end = self.data.find(b'\0', part_str)

        elif offset is not None:
            # Assume if offset is provided, it points to the start
            # of the string
            str_begin = offset
            str_end = self.data.find(b'\0', str_begin)

        else:
            raise ValueError('Either string or offset must be provided.')

        return self._string(str_begin, self._data[str_begin:str_end], self)


class _Patcher(_Assembler, _Disassembler):
    def __init__(self, data: bytes, asm: Ks, disasm: Cs):
        self._data = bytearray(data)

        self._asm = asm
        self._disasm = disasm
        self._disasm.detail = True

    def search_insns(self, *insns: str) -> Optional[_Insn]:
        instructions = ';'.join(insns)
        data = self.asm(instructions)

        offset = self.data.find(data)
        if offset == -1:
            raise eyepatch.SearchError(f'Failed to find instructions: {instructions}')

        return next(self.disasm(offset))
