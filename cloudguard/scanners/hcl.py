"""A small, dependency-free HCL2 parser producing a navigable syntax tree.

Terraform rules are written against structure, not text: a regular expression
cannot tell an ``ingress`` block from an ``egress`` one, nor find the CIDR of a
rule declared three levels deep. This module therefore turns a ``.tf`` file into
:class:`Block` / :class:`Value` nodes that the scanner walks.

Scope — this is deliberately *not* a full HCL implementation. It parses the
declarative subset used by real Terraform code:

* blocks with any number of labels, arbitrarily nested;
* attributes with literal values (strings, numbers, booleans, lists, objects);
* heredocs (``<<EOT`` and the indented ``<<-EOT`` form);
* line (``#``, ``//``) and block (``/* */``) comments.

Everything else — function calls, references, ternaries, ``for`` expressions — is
preserved verbatim as :attr:`Value.raw` so rules can still inspect it, with
:meth:`Value.unwrap_call` available to look inside ``jsonencode({...})``.
"""

from __future__ import annotations

from collections.abc import Iterator
from dataclasses import dataclass, field
from typing import Any

__all__ = ["Block", "HCLParseError", "Value", "parse_expression", "parse_hcl"]

_WHITESPACE = " \t\r"
_IDENT_START = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ_")
_IDENT_CHARS = _IDENT_START | set("0123456789-.")


class HCLParseError(ValueError):
    """Raised when a file cannot be parsed as HCL."""

    def __init__(self, message: str, line: int) -> None:
        super().__init__(f"line {line}: {message}")
        self.line = line


@dataclass
class Value:
    """An attribute value: its source text plus, when possible, a Python literal.

    ``literal`` is ``None`` for anything that is not a constant — a variable
    reference, a function call, an interpolated string. Rules must therefore
    treat ``None`` as *unknown*, never as *absent*.
    """

    raw: str
    line: int
    literal: Any = None

    @property
    def is_literal(self) -> bool:
        """``True`` when the value is a compile-time constant."""
        return self.literal is not None

    def as_str(self) -> str | None:
        """Return the value as a string, or ``None`` if it is not a literal string."""
        return self.literal if isinstance(self.literal, str) else None

    def as_bool(self) -> bool | None:
        """Return the value as a boolean, or ``None`` if it is not a literal boolean."""
        return self.literal if isinstance(self.literal, bool) else None

    def as_int(self) -> int | None:
        """Return the value as an int, or ``None`` if it is not a literal integer."""
        if isinstance(self.literal, bool):
            return None
        return self.literal if isinstance(self.literal, int) else None

    def as_list(self) -> list[Value] | None:
        """Return the value as a list of values, or ``None`` if it is not a list."""
        return self.literal if isinstance(self.literal, list) else None

    def as_object(self) -> dict[str, Value] | None:
        """Return the value as an object, or ``None`` if it is not an object."""
        return self.literal if isinstance(self.literal, dict) else None

    def str_items(self) -> list[str]:
        """Return the literal strings contained in a list value (``[]`` otherwise)."""
        items = self.as_list()
        if items is None:
            return []
        return [s for s in (item.as_str() for item in items) if s is not None]

    def unwrap_call(self, name: str) -> Value | None:
        """Parse the argument of ``name(...)`` when the value is such a call.

        Used to look inside ``jsonencode({ Statement = [...] })`` without
        teaching the whole parser about function calls.
        """
        text = self.raw.strip()
        prefix = f"{name}("
        if not text.startswith(prefix) or not text.endswith(")"):
            return None
        return parse_expression(text[len(prefix) : -1], self.line)

    def __repr__(self) -> str:  # pragma: no cover - debugging helper
        """Readable form used when debugging a rule."""
        return f"Value({self.raw!r}, line={self.line}, literal={self.literal!r})"


@dataclass
class Block:
    """A block (``resource "aws_s3_bucket" "data" { ... }``) or a file body."""

    type: str
    labels: list[str] = field(default_factory=list)
    attributes: dict[str, Value] = field(default_factory=dict)
    blocks: list[Block] = field(default_factory=list)
    line: int = 0

    @property
    def address(self) -> str:
        """Terraform-style address, e.g. ``aws_s3_bucket.data`` or ``variable.password``."""
        if self.type == "resource" and len(self.labels) >= 2:
            return f"{self.labels[0]}.{self.labels[1]}"
        if self.type == "data" and len(self.labels) >= 2:
            return f"data.{self.labels[0]}.{self.labels[1]}"
        return ".".join([self.type, *self.labels]) if self.labels else self.type

    @property
    def resource_type(self) -> str:
        """First label of a ``resource``/``data`` block (``aws_s3_bucket``), else ``""``."""
        return self.labels[0] if self.labels else ""

    @property
    def name(self) -> str:
        """Last label of the block, or its type when it has no label."""
        return self.labels[-1] if self.labels else self.type

    def get(self, name: str) -> Value | None:
        """Return the attribute named ``name``, or ``None``."""
        return self.attributes.get(name)

    def get_str(self, name: str) -> str | None:
        """Return a literal string attribute, or ``None``."""
        value = self.attributes.get(name)
        return value.as_str() if value else None

    def get_bool(self, name: str) -> bool | None:
        """Return a literal boolean attribute, or ``None``."""
        value = self.attributes.get(name)
        return value.as_bool() if value else None

    def get_int(self, name: str) -> int | None:
        """Return a literal integer attribute, or ``None``."""
        value = self.attributes.get(name)
        return value.as_int() if value else None

    def get_blocks(self, *types: str) -> list[Block]:
        """Return the direct child blocks whose type is one of ``types``."""
        return [b for b in self.blocks if b.type in types]

    def walk(self) -> Iterator[Block]:
        """Yield this block and every descendant, depth first."""
        yield self
        for child in self.blocks:
            yield from child.walk()

    def resources(self, *resource_types: str) -> Iterator[Block]:
        """Yield top-level ``resource`` blocks, optionally filtered by type."""
        for block in self.blocks:
            if block.type != "resource" or not block.labels:
                continue
            if resource_types and block.labels[0] not in resource_types:
                continue
            yield block


# ----------------------------------------------------------------------------
# Parser
# ----------------------------------------------------------------------------


class _Parser:
    """Recursive-descent parser over the raw source text."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.pos = 0
        self.line = 1
        self.length = len(text)

    # -- low level helpers ---------------------------------------------------

    def eof(self) -> bool:
        return self.pos >= self.length

    def peek(self, offset: int = 0) -> str:
        index = self.pos + offset
        return self.text[index] if index < self.length else ""

    def advance(self, count: int = 1) -> str:
        chunk = self.text[self.pos : self.pos + count]
        self.line += chunk.count("\n")
        self.pos += count
        return chunk

    def skip_inline_space(self) -> None:
        """Skip spaces, tabs and comments — but stop on a newline."""
        while not self.eof():
            char = self.peek()
            if char in _WHITESPACE:
                self.advance()
            elif char == "#" or (char == "/" and self.peek(1) == "/"):
                while not self.eof() and self.peek() != "\n":
                    self.advance()
            elif char == "/" and self.peek(1) == "*":
                self._skip_block_comment()
            else:
                return

    def skip_space(self) -> None:
        """Skip whitespace — newlines included — and comments."""
        while not self.eof():
            char = self.peek()
            if char in _WHITESPACE or char == "\n":
                self.advance()
            elif char == "#" or (char == "/" and self.peek(1) == "/"):
                while not self.eof() and self.peek() != "\n":
                    self.advance()
            elif char == "/" and self.peek(1) == "*":
                self._skip_block_comment()
            else:
                return

    def _skip_block_comment(self) -> None:
        self.advance(2)
        while not self.eof():
            if self.peek() == "*" and self.peek(1) == "/":
                self.advance(2)
                return
            self.advance()

    def read_identifier(self) -> str:
        start = self.pos
        while not self.eof() and self.peek() in _IDENT_CHARS:
            self.advance()
        return self.text[start : self.pos]

    def read_quoted_string(self) -> str:
        """Consume a double-quoted string and return its *raw* form (quotes included)."""
        start = self.pos
        self.advance()  # opening quote
        while not self.eof():
            char = self.peek()
            if char == "\\":
                self.advance(2)
                continue
            if char == "$" and self.peek(1) == "{":
                self._skip_interpolation()
                continue
            self.advance()
            if char == '"':
                break
        return self.text[start : self.pos]

    def _skip_interpolation(self) -> None:
        """Skip a ``${ ... }`` interpolation, honouring nesting and nested strings."""
        self.advance(2)
        depth = 1
        while not self.eof() and depth:
            char = self.peek()
            if char == '"':
                self.read_quoted_string()
                continue
            if char == "{":
                depth += 1
            elif char == "}":
                depth -= 1
            self.advance()

    def read_heredoc(self) -> str:
        """Consume a ``<<TAG`` / ``<<-TAG`` heredoc and return its raw source."""
        start = self.pos
        self.advance(2)  # '<<'
        if self.peek() == "-":
            self.advance()
        tag = self.read_identifier()
        if not tag:
            raise HCLParseError("heredoc without a delimiter", self.line)
        while not self.eof() and self.peek() != "\n":
            self.advance()
        self.advance()  # newline after the opening tag
        while not self.eof():
            line_start = self.pos
            while not self.eof() and self.peek() != "\n":
                self.advance()
            content = self.text[line_start : self.pos]
            if not self.eof():
                self.advance()  # consume the newline
            if content.strip() == tag:
                break
        return self.text[start : self.pos]

    # -- grammar -------------------------------------------------------------

    def parse_body(self, *, nested: bool) -> Block:
        """Parse a sequence of attributes and blocks until ``}`` or EOF."""
        body = Block(type="__body__", line=self.line)
        while True:
            self.skip_space()
            if self.eof():
                if nested:
                    raise HCLParseError("unterminated block", self.line)
                return body
            if self.peek() == "}":
                if not nested:
                    # Stray brace at top level: skip it rather than failing the file.
                    self.advance()
                    continue
                self.advance()
                return body
            self._parse_item(body)

    def _parse_item(self, body: Block) -> None:
        line = self.line
        char = self.peek()

        if char == '"':
            key = _unquote(self.read_quoted_string())
        elif char in _IDENT_START:
            key = self.read_identifier()
        else:
            # Unknown construct — skip the character and keep going. Being lenient
            # matters more than being strict: one odd line must not blind the scan.
            self.advance()
            return

        self.skip_inline_space()
        nxt = self.peek()

        if nxt == "=" and self.peek(1) != "=":
            self.advance()
            value = self._parse_value()
            body.attributes[key] = value
            return

        if nxt == ":":
            self.advance()
            body.attributes[key] = self._parse_value()
            return

        if nxt == "{":
            self.advance()
            child = self.parse_body(nested=True)
            child.type = key
            child.line = line
            body.blocks.append(child)
            return

        # Labelled block: identifiers and/or quoted strings, then '{'.
        labels: list[str] = []
        while True:
            self.skip_inline_space()
            char = self.peek()
            if char == '"':
                labels.append(_unquote(self.read_quoted_string()))
            elif char in _IDENT_START:
                labels.append(self.read_identifier())
            elif char == "{":
                self.advance()
                child = self.parse_body(nested=True)
                child.type = key
                child.labels = labels
                child.line = line
                body.blocks.append(child)
                return
            else:
                # Not a block after all (e.g. a bare word) — give up on this item.
                return

    def _parse_value(self) -> Value:
        """Parse the expression on the right-hand side of ``=``."""
        self.skip_inline_space()
        # A value may legitimately start on the next line for multi-line collections.
        while self.peek() == "\n":
            self.advance()
            self.skip_inline_space()
        line = self.line
        raw = self._read_expression(stop_chars="")
        return _literal_value(raw.strip(), line)

    def _read_expression(self, stop_chars: str) -> str:
        """Read raw expression text, stopping at a top-level newline or stop char."""
        start = self.pos
        depth = 0
        while not self.eof():
            char = self.peek()
            if char == '"':
                self.read_quoted_string()
                continue
            if char == "<" and self.peek(1) == "<":
                self.read_heredoc()
                # The closing delimiter consumes its own newline, so at the top
                # level the expression ends here — otherwise the next attribute
                # would be swallowed into the heredoc value.
                if depth == 0:
                    break
                continue
            if char == "#" or (char == "/" and self.peek(1) == "/"):
                end = self.pos
                while not self.eof() and self.peek() != "\n":
                    self.advance()
                # Trailing comment: exclude it from the expression text.
                return self.text[start:end]
            if char == "/" and self.peek(1) == "*":
                self._skip_block_comment()
                continue
            if char in "([{":
                depth += 1
            elif char in ")]}":
                if depth == 0:
                    break
                depth -= 1
            elif (char == "\n" and depth == 0) or (depth == 0 and char in stop_chars):
                break
            self.advance()
        return self.text[start : self.pos]


def _unquote(raw: str) -> str:
    """Turn a raw quoted string into its value (best-effort unescaping)."""
    text = raw.strip()
    if len(text) >= 2 and text[0] == '"' and text[-1] == '"':
        text = text[1:-1]
    return text.replace('\\"', '"').replace("\\n", "\n").replace("\\t", "\t").replace("\\\\", "\\")


def _is_plain_string(raw: str) -> bool:
    """``True`` for a quoted string with no interpolation and nothing appended."""
    if len(raw) < 2 or raw[0] != '"' or raw[-1] != '"':
        return False
    if "${" in raw:
        return False
    # Reject "a" == "b" or "a" + var.x: the closing quote must end the expression.
    index = 1
    while index < len(raw):
        char = raw[index]
        if char == "\\":
            index += 2
            continue
        if char == '"':
            return index == len(raw) - 1
        index += 1
    return False


def _split_top_level(text: str) -> list[tuple[str, int]]:
    """Split a collection body on top-level commas/newlines, keeping line offsets."""
    items: list[tuple[str, int]] = []
    depth = 0
    start = 0
    line_offset = 0
    item_line = 0
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            index += 1
            while index < len(text):
                if text[index] == "\\":
                    index += 2
                    continue
                if text[index] == '"':
                    break
                if text[index] == "\n":
                    line_offset += 1
                index += 1
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif char in ",\n" and depth == 0:
            chunk = text[start:index]
            if chunk.strip():
                items.append((chunk, item_line))
            start = index + 1
            if char == "\n":
                line_offset += 1
            item_line = line_offset
        elif char == "\n":
            line_offset += 1
        index += 1
    tail = text[start:]
    if tail.strip():
        items.append((tail, item_line))
    return items


def _strip_comments(text: str) -> str:
    """Remove ``#``/``//`` comments from a collection body, ignoring strings."""
    out: list[str] = []
    index = 0
    while index < len(text):
        char = text[index]
        if char == '"':
            out.append(char)
            index += 1
            while index < len(text):
                out.append(text[index])
                if text[index] == "\\":
                    index += 1
                    if index < len(text):
                        out.append(text[index])
                        index += 1
                    continue
                if text[index] == '"':
                    index += 1
                    break
                index += 1
            continue
        if char == "#" or (char == "/" and index + 1 < len(text) and text[index + 1] == "/"):
            while index < len(text) and text[index] != "\n":
                index += 1
            continue
        out.append(char)
        index += 1
    return "".join(out)


def _literal_value(raw: str, line: int) -> Value:
    """Build a :class:`Value`, resolving the literal form when there is one."""
    text = raw.strip()
    value = Value(raw=text, line=line)

    if not text:
        return value

    if _is_plain_string(text):
        value.literal = _unquote(text)
        return value

    if text.startswith("<<"):
        value.literal = _heredoc_body(text)
        return value

    lowered = text.lower()
    if lowered in ("true", "false"):
        value.literal = lowered == "true"
        return value

    if _looks_numeric(text):
        value.literal = float(text) if ("." in text or "e" in lowered) else int(text)
        return value

    if text.startswith("[") and text.endswith("]"):
        body = _strip_comments(text[1:-1])
        value.literal = [
            _literal_value(chunk.strip(), line + offset) for chunk, offset in _split_top_level(body)
        ]
        return value

    if text.startswith("{") and text.endswith("}"):
        value.literal = _parse_object_body(_strip_comments(text[1:-1]), line)
        return value

    return value


def _parse_object_body(body: str, line: int) -> dict[str, Value]:
    """Parse ``key = value`` / ``key: value`` pairs inside ``{ ... }``."""
    obj: dict[str, Value] = {}
    for chunk, offset in _split_top_level(body):
        key, separator, rest = _split_pair(chunk)
        if not separator:
            continue
        obj[_unquote(key.strip())] = _literal_value(rest.strip(), line + offset)
    return obj


def _split_pair(chunk: str) -> tuple[str, str, str]:
    """Split ``key = value`` on the first top-level ``=`` or ``:``."""
    depth = 0
    index = 0
    while index < len(chunk):
        char = chunk[index]
        if char == '"':
            index += 1
            while index < len(chunk):
                if chunk[index] == "\\":
                    index += 2
                    continue
                if chunk[index] == '"':
                    break
                index += 1
        elif char in "([{":
            depth += 1
        elif char in ")]}":
            depth -= 1
        elif depth == 0 and (char == ":" or (char == "=" and chunk[index : index + 2] != "==")):
            return chunk[:index], char, chunk[index + 1 :]
        index += 1
    return chunk, "", ""


def _heredoc_body(text: str) -> str:
    """Extract the body of a heredoc expression."""
    lines = text.splitlines()
    if not lines:
        return ""
    header = lines[0].strip()
    tag = header.lstrip("<").lstrip("-").strip()
    body: list[str] = []
    for raw_line in lines[1:]:
        if raw_line.strip() == tag:
            break
        body.append(raw_line)
    if header.startswith("<<-"):
        body = [line.lstrip() for line in body]
    return "\n".join(body)


def _looks_numeric(text: str) -> bool:
    try:
        float(text)
    except ValueError:
        return False
    return True


def parse_expression(text: str, line: int = 0) -> Value:
    """Parse a standalone expression — used to look inside ``jsonencode(...)``."""
    return _literal_value(text.strip(), line)


def parse_hcl(text: str) -> Block:
    """Parse an HCL document and return its root body.

    Raises:
        HCLParseError: on a structurally broken document (unterminated block…).
    """
    parser = _Parser(text)
    body = parser.parse_body(nested=False)
    body.type = "__root__"
    return body
