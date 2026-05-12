from .awk import AwkGenerator
from .bash import BashGenerator
from .cradle import CradleGenerator
from .csharp import CSharpGenerator
from .golang import GolangGenerator
from .lolbins import LOLBinsGenerator
from .lua import LuaGenerator
from .netcat import NetcatGenerator
from .nodejs import NodeJSGenerator
from .openssl import OpenSSLGenerator
from .perl import PerlGenerator
from .php import PHPGenerator
from .powershell import PowerShellGenerator
from .python_shell import PythonGenerator
from .ruby import RubyGenerator
from .socat import SocatGenerator

REGISTRY: dict[str, type] = {
    "awk": AwkGenerator,
    "bash": BashGenerator,
    "cradle": CradleGenerator,
    "csharp": CSharpGenerator,
    "golang": GolangGenerator,
    "lolbins": LOLBinsGenerator,
    "lua": LuaGenerator,
    "nc": NetcatGenerator,
    "netcat": NetcatGenerator,
    "nodejs": NodeJSGenerator,
    "openssl": OpenSSLGenerator,
    "perl": PerlGenerator,
    "php": PHPGenerator,
    "powershell": PowerShellGenerator,
    "ps": PowerShellGenerator,
    "python3": PythonGenerator,
    "ruby": RubyGenerator,
    "socat": SocatGenerator,
}

SUPPORTED_LANGUAGES = sorted(REGISTRY.keys())
