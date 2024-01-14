from dataclasses import dataclass
from enum import Enum


class iBootStage(Enum):
    STAGE_1 = 1
    STAGE_2 = 2


@dataclass
class iBootVersion:
    major: int
    minor: int
    patch: int

    def __repr__(self) -> str:
        return f'iBoot-{self.major}.{self.minor}.{self.patch}'

    def __gt__(self, other: 'iBootVersion') -> bool:
        if not isinstance(other, iBootVersion):
            raise TypeError(f'Cannot compare iBootVersion with {type(other)}')

        return (self.major, self.minor, self.patch) > (
            other.major,
            other.minor,
            other.patch,
        )

    def __lt__(self, other: 'iBootVersion') -> bool:
        if not isinstance(other, iBootVersion):
            raise TypeError(f'Cannot compare iBootVersion with {type(other)}')

        return (self.major, self.minor, self.patch) < (
            other.major,
            other.minor,
            other.patch,
        )

    def __eq__(self, other: 'iBootVersion') -> bool:
        if not isinstance(other, iBootVersion):
            raise TypeError(f'Cannot compare iBootVersion with {type(other)}')

        return (self.major, self.minor, self.patch) == (
            other.major,
            other.minor,
            other.patch,
        )
