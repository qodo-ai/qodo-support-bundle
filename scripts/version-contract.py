#!/usr/bin/env python3
"""Validate and order the strict installer version metadata contract."""

import json
import re
import sys
from pathlib import Path

VERSION_PATTERN = re.compile(
    r"^(?P<major>[0-9]+)\.(?P<minor>[0-9]+)\.(?P<patch>[0-9]+)"
    r"(?P<suffix>[.-][0-9A-Za-z][0-9A-Za-z.-]*)?$"
)


def parse_version(value: str) -> tuple[int, int, int, tuple[tuple[int, object], ...]]:
    match = VERSION_PATTERN.fullmatch(value)
    if match is None:
        raise ValueError(f"invalid version: {value}")
    suffix = match.group("suffix")
    identifiers: list[tuple[int, object]] = []
    if suffix:
        for identifier in suffix[1:].split("."):
            if identifier.isdigit():
                identifiers.append((0, int(identifier)))
            else:
                identifiers.append((1, identifier.lower()))
    else:
        identifiers.append((2, ""))
    return (
        int(match.group("major")),
        int(match.group("minor")),
        int(match.group("patch")),
        tuple(identifiers),
    )


def unique_object(pairs: list[tuple[str, object]]) -> dict[str, object]:
    value: dict[str, object] = {}
    for key, item in pairs:
        if key in value:
            raise ValueError(f"duplicate JSON property: {key}")
        value[key] = item
    return value


def read_metadata(path: str) -> str:
    value = json.loads(
        Path(path).read_text(encoding="utf-8"),
        object_pairs_hook=unique_object,
    )
    if (
        not isinstance(value, dict)
        or list(value.keys()) != ["version"]
        or not isinstance(value["version"], str)
    ):
        raise ValueError("version.json must contain only a string version property")
    parse_version(value["version"])
    return value["version"]


def main() -> int:
    try:
        if len(sys.argv) == 3 and sys.argv[1] == "render":
            parse_version(sys.argv[2])
            print(json.dumps({"version": sys.argv[2]}, separators=(", ", ": ")))
            return 0
        if len(sys.argv) == 4 and sys.argv[1] == "allow-update":
            current = read_metadata(sys.argv[2])
            candidate = sys.argv[3]
            if parse_version(candidate) < parse_version(current):
                raise ValueError(
                    f"refusing version downgrade from {current} to {candidate}"
                )
            print(current)
            return 0
        if len(sys.argv) == 3 and sys.argv[1] == "read":
            print(read_metadata(sys.argv[2]))
            return 0
    except (OSError, UnicodeError, json.JSONDecodeError, ValueError) as error:
        print(f"version-contract: {error}", file=sys.stderr)
        return 1
    print(
        "usage: version-contract.py render VERSION | "
        "read VERSION_JSON | allow-update CURRENT_JSON CANDIDATE",
        file=sys.stderr,
    )
    return 2


if __name__ == "__main__":
    raise SystemExit(main())
