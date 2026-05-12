from .bash import BashGenerator
from .python_shell import PythonGenerator
from .perl import PerlGenerator
from .php import PHPGenerator
from .ruby import RubyGenerator
from .netcat import NetcatGenerator
from .powershell import PowerShellGenerator
from .awk import AwkGenerator
from .lua import LuaGenerator

REGISTRY: dict[str, type] = {
    "bash": BashGenerator,
    "python3": PythonGenerator,
    "perl": PerlGenerator,
    "php": PHPGenerator,
    "ruby": RubyGenerator,
    "netcat": NetcatGenerator,
    "nc": NetcatGenerator,
    "powershell": PowerShellGenerator,
    "ps": PowerShellGenerator,
    "awk": AwkGenerator,
    "lua": LuaGenerator,
}

SUPPORTED_LANGUAGES = sorted(REGISTRY.keys())
