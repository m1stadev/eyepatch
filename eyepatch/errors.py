class EyepatchError(Exception):
    pass


class DisassemblyError(EyepatchError):
    pass


class SearchError(DisassemblyError):
    pass


class AssemblyError(EyepatchError):
    pass


class InsnError(EyepatchError):
    pass
