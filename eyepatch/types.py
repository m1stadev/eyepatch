from dataclasses import dataclass


@dataclass
class Insn:
    mnemonic: str
    op_str: str
    data: bytes


@dataclass
class Xref:
    from_: Insn
    to: Insn
