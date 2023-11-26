from dataclasses import dataclass


@dataclass
class Insn:
    offset: int
    mnemonic: str
    op_str: str
    data: bytes


@dataclass
class Xref:
    from_: Insn
    to: Insn


@dataclass
class String:
    string: str
    offset: int
    length: int
