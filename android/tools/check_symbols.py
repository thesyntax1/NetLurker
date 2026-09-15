#!/usr/bin/env python3
"""Resolve every project-internal symbol the Kotlin sources reference.

Gradle is the only real compiler here and a cold run costs minutes of CI, so this is a
cheap gate in front of it: it catches the class of mistake that is easy to make when
editing Kotlin without an IDE and impossible to notice by reading — an import for a name
that does not exist, or an enum constant that was never declared. Both fail the build with
"Unresolved reference" and nothing else.

It is deliberately not a parser. It collects top-level declarations by pattern and matches
them against `import dev.netlurker.android...` lines, then does the same for `Enum.MEMBER`
references against the members it found inside each enum body. Anything it cannot resolve is
reported; anything it can resolve says nothing about whether the code is correct, only that
the name exists.
"""
from __future__ import annotations

import os
import re
import sys

SRC_ROOT = os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "app", "src")
SOURCE_SETS = ("main/kotlin", "test/kotlin", "androidTest/kotlin")

DECL = re.compile(
    r'^(?:@\w+\s+)*(?:public |internal |private )?'
    r'(?:data |sealed |abstract |open |value |enum |annotation |expect |actual )*'
    r'(?:class|object|interface|fun|val|var|typealias)\s+([A-Za-z_]\w*)',
    re.M,
)
IMPORT = re.compile(r'^import (dev\.netlurker\.android(?:\.\w+)*)\.([A-Za-z_]\w*)\s*$', re.M)
ENUM_HEAD = re.compile(r'enum class (\w+)\s*(?:\([^)]*\))?\s*\{')
ENUM_REF = re.compile(r'\b([A-Z]\w*)\.([A-Z][A-Z0-9_]+)\b')
NAME = re.compile(r'[A-Za-z_]\w*')
# The same non-repeatable annotation twice on one declaration. Editing a test file by
# inserting a block above an existing function leaves the old annotation behind, and Kotlin
# rejects it with a message that does not name the duplicate.
REPEATED_ANNOTATION = re.compile(
    r'(@[A-Z]\w*(?:\([^)]*\))?)\s*\n(?:\s*@[A-Z]\w*(?:\([^)]*\))?\s*\n)*\s*\1\b'
)
PACKAGE = re.compile(r'^package ([\w.]+)\s*$', re.M)
# Strong signals that a capitalized identifier is being used as a type or an object, rather
# than merely appearing in prose: static access, construction, a type position, a generic
# argument or a supertype list.
TYPE_USE = re.compile(r'(?<![\w.])([A-Z]\w+)\s*(?:\.\w|\(|\s*[>,)]|\s*$)')


def kotlin_files(base: str):
    for root, _dirs, files in os.walk(os.path.join(SRC_ROOT, base)):
        for name in sorted(files):
            if name.endswith(".kt"):
                path = os.path.join(root, name)
                with open(path, encoding="utf-8") as handle:
                    yield os.path.relpath(path, SRC_ROOT), handle.read()


def strip_noise(text: str) -> str:
    """Drop comments and string literals so neither can look like code."""
    text = re.sub(r'/\*.*?\*/', ' ', text, flags=re.S)
    text = re.sub(r'"""(?:.|\n)*?"""', '""', text)
    text = re.sub(r'"(?:\\.|[^"\\])*"', '""', text)
    text = re.sub(r'//[^\n]*', '', text)
    return text


def enum_body(text: str, open_brace: int) -> str:
    """The text between an enum's braces, found by counting rather than by regex."""
    depth, index = 0, open_brace
    while index < len(text):
        if text[index] == "{":
            depth += 1
        elif text[index] == "}":
            depth -= 1
            if depth == 0:
                return text[open_brace + 1:index]
        index += 1
    return ""


def enum_members(text: str) -> dict[str, set[str]]:
    found: dict[str, set[str]] = {}
    for match in ENUM_HEAD.finditer(text):
        body = enum_body(text, match.end() - 1).split(";")[0]
        names = set()
        for chunk in body.split(","):
            head = chunk.strip().split("(")[0].strip()
            if NAME.fullmatch(head or ""):
                names.add(head)
        found[match.group(1)] = names
    return found


def collect() -> tuple[dict[str, str], set[str], dict[str, set[str]]]:
    """name -> declaring package, every declared name, and each enum's members."""
    home: dict[str, str] = {}
    declared: set[str] = set()
    enums: dict[str, set[str]] = {}
    for _path, source in kotlin_files(SOURCE_SETS[0]):
        clean = strip_noise(source)
        match = PACKAGE.search(clean)
        package = match.group(1) if match else ""
        for name in DECL.findall(clean):
            declared.add(name)
            home.setdefault(name, package)
        for name, members in enum_members(clean).items():
            enums.setdefault(name, set()).update(members)
    return home, declared, enums


def main() -> int:
    home, declared, enums = collect()

    unresolved_imports: list[str] = []
    unresolved_constants: list[str] = []
    missing_imports: list[str] = []
    repeated: list[str] = []
    for source_set in SOURCE_SETS:
        for path, source in kotlin_files(source_set):
            clean = strip_noise(source)
            imported = {m.group(2) for m in IMPORT.finditer(source)}
            own = PACKAGE.search(clean)
            own_package = own.group(1) if own else ""
            local = set(DECL.findall(clean))
            for match in IMPORT.finditer(source):
                if match.group(2) not in declared:
                    unresolved_imports.append(
                        "%s: import %s.%s has no declaration"
                        % (path, match.group(1), match.group(2))
                    )
            for match in ENUM_REF.finditer(clean):
                owner, member = match.group(1), match.group(2)
                if owner in enums and member not in enums[owner]:
                    unresolved_constants.append(
                        "%s: %s.%s is not a member (declared: %s)"
                        % (path, owner, member, ", ".join(sorted(enums[owner])))
                    )
            for match in REPEATED_ANNOTATION.finditer(clean):
                repeated.append(
                    "%s: %s is applied twice to the same declaration"
                    % (path, match.group(1))
                )
            # A project type used from another package needs an import; forgetting one is
            # the "Unresolved reference" that costs a whole CI run to discover.
            for match in TYPE_USE.finditer(clean):
                name = match.group(1)
                if name in home and home[name] != own_package \
                        and name not in imported and name not in local:
                    missing_imports.append(
                        "%s: %s is used but never imported (declared in %s)"
                        % (path, name, home[name])
                    )

    print("declarations: %d, enums: %s"
          % (len(declared), {k: sorted(v) for k, v in sorted(enums.items())}))
    report = (sorted(set(unresolved_imports)) + sorted(set(unresolved_constants))
              + sorted(set(missing_imports)) + sorted(set(repeated)))
    for line in report:
        print("  " + line)
    problems = len(report)
    print("symbol check: %d problem(s)" % problems)
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
