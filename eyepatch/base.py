from sys import version_info
from typing import Generator, Optional, Union

from capstone import Cs, CsError, CsInsn
from keystone import Ks, KsError

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
            # TODO: Raise error
            pass

        return asm


class _Insn:
    def __init__(
        self,
        offset: int,
        data: bytes,
        info: Optional[CsInsn] = None,
        patcher: Optional['_Patcher'] = None,
    ):
        self._offset = offset
        self._data = bytearray(data)

        self._patcher = patcher

        if self._patcher is not None and info is None:
            self._info = next(self.patcher._disasm(data, 0))
        else:
            self._info = info

    def __next__(self) -> Self:
        if self.patcher is None:
            # TODO: raise error
            pass

        return next(self.patcher.disasm(self.offset + 0x4))

    def __repr__(self) -> str:
        if self.info is not None:
            insn = f'{self.info.mnemonic} {self.info.op_str}'
            return f'0x{self.offset:x}: {self.info.mnemonic} {self.info.op_str}'
        else:
            insn = self.data.hex()

        return f'0x{self.offset:x}: {insn}'

    @property
    def info(self) -> Optional[CsInsn]:
        return self._info

    @property
    def data(self) -> bytes:
        return bytes(self._data)

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def patcher(self) -> Optional['_Patcher']:
        return self._patcher

    def patch(self, insn: str) -> None:
        data = self.patcher.asm(insn)
        if len(data) != len(data):
            raise ValueError(
                'New instruction must be the same size as the current instruction'
            )

        self._data = bytearray(data)
        self.patcher._data[self.offset : self.offset + len(data)] = data
        self._info = self.patcher.disasm(self.offset)


class _ByteString:
    def __init__(self, offset: int, data: bytes, patcher: Optional['_Patcher'] = None):
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
    def patcher(self) -> Optional['_Patcher']:
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
            # TODO: raise error
            pass

        if len(oldvalue) > len(newvalue):
            oldvalue += b' ' * (len(newvalue) - len(oldvalue))
        elif len(oldvalue) < len(newvalue):
            # TODO: raise error
            pass

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
            return  # TODO: Raise error

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
        self,
        insn_name: str,
        offset: int = 0,
        skip: int = 0,
    ) -> Optional[_insn]:
        for insn in self.disasm(offset):
            if insn.info.mnemonic == insn_name:
                if skip == 0:
                    return insn

                skip -= 1

    def search_imm(self, imm: int, offset: int = 0, skip: int = 0) -> Optional[_insn]:
        for insn in self.disasm(offset):
            if any(imm == op.imm for op in insn.info.operands):
                if skip == 0:
                    return insn

                skip -= 1

    def search_string(
        self, string: Union[str, bytes], end: Optional[bool] = False
    ) -> Optional[_string]:
        if isinstance(string, str):
            string = string.encode()

        start = self._data.find(string)
        if start == -1:
            return None

        if end is True:
            end = start + len(string)
        else:
            end = self._data.find(b'\0', start)

        return self._string(start, self._data[start:end], self)


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
            return None

        return next(self.disasm(offset))
