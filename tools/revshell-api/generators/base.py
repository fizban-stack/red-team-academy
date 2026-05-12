import random
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass

# Shell built-ins and common names to avoid as random variable names
_RESERVED = {
    "sh", "bash", "zsh", "nc", "ip", "ls", "cd", "rm", "cp", "mv",
    "ps", "id", "if", "do", "fi", "in", "fd", "io", "os", "cmd",
    "pw", "py", "rb", "go", "sh", "fn", "is", "it", "me", "my",
}


@dataclass
class ShellResult:
    command: str
    variant: str
    language: str
    arch: str


class RandomNamePool:
    """Generates collision-safe random variable names."""

    def __init__(self, length_range: tuple[int, int] = (4, 8)):
        self._used: set[str] = set()
        self._length_range = length_range

    def get(self) -> str:
        for _ in range(10_000):
            length = random.randint(*self._length_range)
            name = random.choice(string.ascii_lowercase) + "".join(
                random.choices(string.ascii_lowercase + string.digits, k=length - 1)
            )
            if name not in _RESERVED and name not in self._used:
                self._used.add(name)
                return name
        raise RuntimeError("RandomNamePool exhausted — increase length_range")


class ShellGenerator(ABC):
    """Base class for all reverse shell generators."""

    language: str = ""

    def generate(self, lhost: str, lport: int, arch: str, obfuscate: bool) -> ShellResult:
        names = RandomNamePool() if obfuscate else None
        return self._generate(lhost, lport, arch, names)

    @abstractmethod
    def _generate(
        self, lhost: str, lport: int, arch: str, names: RandomNamePool | None
    ) -> ShellResult:
        ...

    def _var(self, default: str, names: RandomNamePool | None) -> str:
        return names.get() if names else default
