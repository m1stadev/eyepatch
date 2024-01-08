from typing import Optional, Union

import eyepatch.base


class _ByteString:
    def __init__(
        self, offset: int, data: bytes, patcher: Optional[eyepatch.base._Patcher] = None
    ):
        self._offset = offset
        self._data = data
        self._patcher = patcher

    def __repr__(self) -> str:
        return f'0x{self.offset:x}: "{self.string}"'

    @property
    def data(self) -> bytes:
        return self._data

    @property
    def string(self) -> str:
        return self._data.decode()

    @property
    def offset(self) -> int:
        return self._offset

    @property
    def patcher(self) -> Optional[eyepatch.base._Patcher]:
        return self._patcher

    def replace(
        self,
        oldvalue: Union[str, bytes],
        newvalue: Union[str, bytes],
        count: Optional[int],
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
