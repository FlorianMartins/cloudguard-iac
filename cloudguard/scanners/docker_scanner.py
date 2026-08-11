r"""Dockerfile scanner — instruction-level analysis of container build files.

The file is first normalised into :class:`Instruction` records (comments removed,
``\\`` continuations joined, heredocs consumed) while keeping the original line
number of every instruction, then split into build stages.

Stage awareness matters: only the *last* stage ends up in the published image, so
running as root in a builder stage is fine while running as root in the final
stage is not. Rules that describe the shipped artefact (``USER``, ``HEALTHCHECK``)
therefore only look at the final stage.
"""

from __future__ import annotations

import re
import shlex
from dataclasses import dataclass, field
from pathlib import Path

from cloudguard.models import Finding, Severity
from cloudguard.scanners.base import SENSITIVE_NAME_TOKENS, BaseScanner

#: Ports that should never be exposed by an application image.
DANGEROUS_PORTS: dict[int, str] = {
    21: "FTP",
    22: "SSH",
    23: "Telnet",
    111: "rpcbind",
    135: "MSRPC",
    445: "SMB",
    512: "rexec",
    513: "rlogin",
    514: "rsh",
    2375: "Docker daemon (plaintext, root-equivalent)",
    2376: "Docker daemon",
    3389: "RDP",
    5900: "VNC",
}

#: Filenames recognised as Dockerfiles.
_DOCKERFILE_RE = re.compile(r"^(dockerfile|containerfile)(\..+)?$|.+\.dockerfile$", re.IGNORECASE)

#: ``curl … | sh`` and friends.
_PIPE_TO_SHELL_RE = re.compile(
    r"\b(?:curl|wget|fetch)\b[^|]*\|\s*(?:sudo\s+)?(?:/bin/)?(?:ba|z|k|a)?sh\b"
)

_CHMOD_777_RE = re.compile(r"\bchmod\b[^\n;&|]*\b(?:0?777|a\+rwx|ugo\+rwx)\b")
_SUDO_RE = re.compile(
    r"\b(?:apt-get\s+install|apk\s+add|yum\s+install|dnf\s+install)\b[^\n]*\bsudo\b"
    r"|\bsudo\s+\S"
)
_APT_UPGRADE_RE = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*(?:upgrade|dist-upgrade)\b")
_APT_INSTALL_RE = re.compile(r"\bapt(?:-get)?\s+(?:-\S+\s+)*install\b")
_APK_ADD_RE = re.compile(r"\bapk\s+add\b")
_PIP_INSTALL_RE = re.compile(r"\bpip3?\s+install\b([^\n;&|]*)")
_NPM_INSTALL_RE = re.compile(r"\bnpm\s+(?:install|i)\b([^\n;&|]*)")
_SECRET_VALUE_RE = re.compile(
    r"(?:AKIA|ASIA)[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9]{16,}|-----BEGIN [A-Z ]*PRIVATE KEY-----"
)

#: Values that clearly are not real secrets.
_PLACEHOLDER_VALUES: frozenset[str] = frozenset(
    {
        "",
        "changeme",
        "todo",
        "none",
        "null",
        "unset",
        "placeholder",
        "example",
        "xxx",
        "false",
        "true",
        "0",
        "1",
    }
)


@dataclass
class Instruction:
    """One logical Dockerfile instruction."""

    keyword: str
    value: str
    line: int
    raw: str

    @property
    def words(self) -> list[str]:
        """Shell-split arguments, falling back to a naive split on quoting errors."""
        try:
            return shlex.split(self.value, posix=True)
        except ValueError:
            return self.value.split()


@dataclass
class Stage:
    """A build stage: its ``FROM`` plus every instruction until the next one."""

    from_instruction: Instruction
    image: str
    alias: str = ""
    instructions: list[Instruction] = field(default_factory=list)

    @property
    def line(self) -> int:
        """Line of the ``FROM`` opening the stage."""
        return self.from_instruction.line

    def of(self, *keywords: str) -> list[Instruction]:
        """Instructions of the stage matching the given keywords."""
        return [i for i in self.instructions if i.keyword in keywords]


def parse_dockerfile(text: str) -> list[Instruction]:
    """Turn Dockerfile source into logical instructions with their line numbers."""
    instructions: list[Instruction] = []
    lines = text.splitlines()
    index = 0
    escape = "\\"

    while index < len(lines):
        raw_line = lines[index]
        stripped = raw_line.strip()

        # Parser directives (# syntax=, # escape=) only matter before the first
        # instruction; the escape one changes how continuations are written.
        if stripped.startswith("#"):
            directive = re.match(r"#\s*escape\s*=\s*(\S)", stripped, re.IGNORECASE)
            if directive and not instructions:
                escape = directive.group(1)
            index += 1
            continue

        if not stripped:
            index += 1
            continue

        start_line = index + 1
        collected = [stripped]
        while collected[-1].rstrip().endswith(escape) and index + 1 < len(lines):
            collected[-1] = collected[-1].rstrip()[: -len(escape)].rstrip()
            index += 1
            nxt = lines[index].strip()
            if nxt.startswith("#"):
                collected.append("")
                continue
            collected.append(nxt)

        logical = " ".join(part for part in collected if part).strip()
        index += 1

        parts = logical.split(maxsplit=1)
        if not parts:
            continue
        keyword = parts[0].upper()
        value = parts[1].strip() if len(parts) > 1 else ""

        # RUN <<EOF … EOF heredoc form: absorb the body into the value.
        heredoc = re.search(r"<<-?\s*[\"']?([A-Za-z_][A-Za-z0-9_]*)[\"']?", value)
        if heredoc and keyword in ("RUN", "COPY"):
            tag = heredoc.group(1)
            body: list[str] = []
            while index < len(lines) and lines[index].strip() != tag:
                body.append(lines[index])
                index += 1
            index += 1  # closing tag
            value = value + "\n" + "\n".join(body)

        instructions.append(Instruction(keyword=keyword, value=value, line=start_line, raw=logical))

    return instructions


def split_stages(instructions: list[Instruction]) -> list[Stage]:
    """Group instructions into build stages."""
    stages: list[Stage] = []
    for instruction in instructions:
        if instruction.keyword == "FROM":
            words = instruction.value.split()
            image = words[0] if words else ""
            alias = ""
            if len(words) >= 3 and words[1].upper() == "AS":
                alias = words[2]
            stages.append(Stage(from_instruction=instruction, image=image, alias=alias))
        elif stages:
            stages[-1].instructions.append(instruction)
    return stages


class DockerScanner(BaseScanner):
    """Detect insecure practices in Dockerfiles."""

    name = "docker"
    category = "docker"

    def matches(self, path: Path) -> bool:
        """``True`` for ``Dockerfile``, ``Dockerfile.prod``, ``api.dockerfile``."""
        return bool(_DOCKERFILE_RE.match(path.name))

    def analyse(self, text: str, display_path: str) -> list[Finding]:
        """Analyse one Dockerfile."""
        self.set_source(text, display_path)
        instructions = parse_dockerfile(text)
        stages = split_stages(instructions)
        if not stages:
            return []

        findings: list[Finding] = []
        findings.extend(self._check_base_images(stages))
        findings.extend(self._check_final_user(stages))
        findings.extend(self._check_healthcheck(stages))
        for instruction in instructions:
            findings.extend(self._check_instruction(instruction))
        return sorted(findings, key=lambda f: (f.line, f.rule_id))

    # -- stage level ---------------------------------------------------------

    def _check_base_images(self, stages: list[Stage]) -> list[Finding]:
        findings: list[Finding] = []
        aliases = {stage.alias for stage in stages if stage.alias}
        for stage in stages:
            image = stage.image
            if not image or image in aliases or image.lower() == "scratch":
                continue
            if image.startswith("$") or "${" in image:
                continue  # build-arg driven, resolved at build time
            if "@sha256:" in image:
                continue
            name, _, tag = image.rpartition(":")
            if not name or "/" in tag:  # no tag at all (":" belonged to a registry port)
                tag = ""
            if tag and tag.lower() != "latest":
                continue
            detail = 'uses the "latest" tag' if tag else "has no tag (implicitly latest)"
            findings.append(
                self.finding(
                    "CG_DOCKER_002",
                    line=stage.line,
                    resource=stage.alias or image,
                    message=f"base image {image!r} {detail}",
                )
            )
        return findings

    def _check_final_user(self, stages: list[Stage]) -> list[Finding]:
        """Only the final stage ships, so only its effective user matters."""
        final = stages[-1]
        chain = self._stage_chain(stages, final)
        last_user: Instruction | None = None
        for stage in chain:
            for instruction in stage.of("USER"):
                last_user = instruction

        if last_user is None:
            return [
                self.finding(
                    "CG_DOCKER_001",
                    line=final.line,
                    resource=final.alias or final.image,
                    message="no USER instruction: the container runs as root (uid 0)",
                )
            ]

        user = last_user.value.split(":", 1)[0].strip().strip("\"'")
        if user in ("root", "0"):
            return [
                self.finding(
                    "CG_DOCKER_001",
                    line=last_user.line,
                    resource=final.alias or final.image,
                    message=f'USER is explicitly set to "{user}"',
                )
            ]
        return []

    @staticmethod
    def _stage_chain(stages: list[Stage], target: Stage) -> list[Stage]:
        """Return ``target`` preceded by the stages it inherits from."""
        by_alias = {stage.alias: stage for stage in stages if stage.alias}
        chain = [target]
        seen = {id(target)}
        current = target
        while current.image in by_alias:
            parent = by_alias[current.image]
            if id(parent) in seen:
                break  # cyclic FROM, malformed file
            seen.add(id(parent))
            chain.insert(0, parent)
            current = parent
        return chain

    def _check_healthcheck(self, stages: list[Stage]) -> list[Finding]:
        final = stages[-1]
        for stage in self._stage_chain(stages, final):
            for instruction in stage.of("HEALTHCHECK"):
                if instruction.value.strip().upper() != "NONE":
                    return []
        return [
            self.finding(
                "CG_DOCKER_011",
                line=final.line,
                resource=final.alias or final.image,
                message="the final stage declares no HEALTHCHECK",
            )
        ]

    # -- instruction level ---------------------------------------------------

    def _check_instruction(self, instruction: Instruction) -> list[Finding]:
        keyword = instruction.keyword
        if keyword == "EXPOSE":
            return self._check_expose(instruction)
        if keyword == "RUN":
            return self._check_run(instruction)
        if keyword in ("ENV", "ARG", "LABEL"):
            return self._check_env(instruction)
        if keyword == "ADD":
            return self._check_add(instruction)
        if keyword == "COPY":
            return self._check_copy(instruction)
        if keyword == "MAINTAINER":
            return [
                self.finding(
                    "CG_DOCKER_013",
                    line=instruction.line,
                    resource="MAINTAINER",
                    message="MAINTAINER is deprecated in favour of OCI labels",
                )
            ]
        return []

    def _check_expose(self, instruction: Instruction) -> list[Finding]:
        findings: list[Finding] = []
        for token in instruction.value.replace(",", " ").split():
            port_text = token.split("/", 1)[0]
            try:
                port = int(port_text)
            except ValueError:
                continue
            if port in DANGEROUS_PORTS:
                findings.append(
                    self.finding(
                        "CG_DOCKER_003",
                        line=instruction.line,
                        resource=f"EXPOSE {port}",
                        message=f"port {port} ({DANGEROUS_PORTS[port]}) is exposed by the image",
                    )
                )
        return findings

    def _check_run(self, instruction: Instruction) -> list[Finding]:
        findings: list[Finding] = []
        command = instruction.value

        if _PIPE_TO_SHELL_RE.search(command):
            findings.append(
                self.finding(
                    "CG_DOCKER_004",
                    line=instruction.line,
                    resource="RUN",
                    message="a remote script is downloaded and piped straight into a shell",
                )
            )

        if _SECRET_VALUE_RE.search(command):
            findings.append(
                self.finding(
                    "CG_DOCKER_005",
                    line=instruction.line,
                    resource="RUN",
                    message="the command line contains what looks like a live credential",
                )
            )

        if _SUDO_RE.search(command):
            findings.append(
                self.finding(
                    "CG_DOCKER_007",
                    line=instruction.line,
                    resource="RUN",
                    message="sudo is installed or used inside the image",
                )
            )

        if _CHMOD_777_RE.search(command):
            findings.append(
                self.finding(
                    "CG_DOCKER_008",
                    line=instruction.line,
                    resource="RUN",
                    message="files are made world-writable (chmod 777)",
                )
            )

        if _APT_UPGRADE_RE.search(command):
            findings.append(
                self.finding(
                    "CG_DOCKER_014",
                    line=instruction.line,
                    resource="RUN",
                    message="apt upgrade/dist-upgrade makes the build non-reproducible",
                )
            )

        if _APT_INSTALL_RE.search(command):
            problems = []
            if "--no-install-recommends" not in command:
                problems.append("--no-install-recommends is missing")
            if "/var/lib/apt/lists" not in command:
                problems.append("the apt lists are not removed")
            if problems:
                findings.append(
                    self.finding(
                        "CG_DOCKER_010",
                        line=instruction.line,
                        resource="RUN",
                        message="apt-get install: " + " and ".join(problems),
                    )
                )

        if _APK_ADD_RE.search(command) and "--no-cache" not in command:
            findings.append(
                self.finding(
                    "CG_DOCKER_010",
                    line=instruction.line,
                    resource="RUN",
                    message="apk add is used without --no-cache",
                )
            )

        findings.extend(self._check_unpinned_packages(instruction, command))
        return findings

    def _check_unpinned_packages(self, instruction: Instruction, command: str) -> list[Finding]:
        findings: list[Finding] = []

        for match in _PIP_INSTALL_RE.finditer(command):
            packages = [
                token
                for token in match.group(1).split()
                if not token.startswith("-") and token not in (".", "..")
            ]
            if "-r" in match.group(1) or "--requirement" in match.group(1):
                continue
            unpinned = [p for p in packages if not re.search(r"[=<>~]=|@", p)]
            if unpinned:
                findings.append(
                    self.finding(
                        "CG_DOCKER_009",
                        line=instruction.line,
                        resource="RUN pip install",
                        message="unpinned Python package(s): " + ", ".join(sorted(unpinned)),
                    )
                )

        for match in _NPM_INSTALL_RE.finditer(command):
            packages = [token for token in match.group(1).split() if not token.startswith("-")]
            unpinned = [p for p in packages if "@" not in p.lstrip("@")]
            if unpinned:
                findings.append(
                    self.finding(
                        "CG_DOCKER_009",
                        line=instruction.line,
                        resource="RUN npm install",
                        message="unpinned npm package(s): " + ", ".join(sorted(unpinned)),
                    )
                )

        return findings

    def _check_env(self, instruction: Instruction) -> list[Finding]:
        findings: list[Finding] = []
        for name, value in _parse_key_values(instruction.value):
            lowered = name.lower()
            looks_sensitive = any(token in lowered for token in SENSITIVE_NAME_TOKENS)
            cleaned = value.strip().strip("\"'")

            if _SECRET_VALUE_RE.search(value):
                findings.append(
                    self.finding(
                        "CG_DOCKER_005",
                        line=instruction.line,
                        resource=f"{instruction.keyword} {name}",
                        message=f"{name} embeds a recognisable credential in the image",
                    )
                )
                continue

            if not looks_sensitive:
                continue
            if cleaned.lower() in _PLACEHOLDER_VALUES or cleaned.startswith("$"):
                continue
            if instruction.keyword == "ARG" and not cleaned:
                continue

            findings.append(
                self.finding(
                    "CG_DOCKER_005",
                    line=instruction.line,
                    resource=f"{instruction.keyword} {name}",
                    message=(
                        f"{name} bakes a secret into the image layers "
                        "(readable via `docker history`)"
                    ),
                    severity=Severity.CRITICAL
                    if instruction.keyword != "LABEL"
                    else Severity.MEDIUM,
                )
            )
        return findings

    def _check_add(self, instruction: Instruction) -> list[Finding]:
        if re.search(r"\b(?:https?|ftp)://", instruction.value):
            return [
                self.finding(
                    "CG_DOCKER_006",
                    line=instruction.line,
                    resource="ADD",
                    message="ADD downloads a remote artefact without integrity verification",
                )
            ]
        return []

    def _check_copy(self, instruction: Instruction) -> list[Finding]:
        words = [w for w in instruction.words if not w.startswith("--")]
        if len(words) >= 2 and words[0] in (".", "./"):
            return [
                self.finding(
                    "CG_DOCKER_012",
                    line=instruction.line,
                    resource="COPY",
                    message="the whole build context is copied into the image",
                )
            ]
        return []


def _parse_key_values(value: str) -> list[tuple[str, str]]:
    """Parse ``KEY=value KEY2="other"`` and the legacy ``KEY value`` forms."""
    text = value.strip()
    if not text:
        return []

    if "=" not in text:
        parts = text.split(maxsplit=1)
        return [(parts[0], parts[1] if len(parts) > 1 else "")]

    try:
        tokens = shlex.split(text, posix=True)
    except ValueError:
        tokens = text.split()

    pairs: list[tuple[str, str]] = []
    for token in tokens:
        if "=" not in token:
            continue
        name, _, item = token.partition("=")
        pairs.append((name.strip(), item))
    return pairs
