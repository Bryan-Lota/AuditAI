import re

PRAGMA_PATTERN = re.compile(r"pragma\s+solidity\s+([^;]+);", re.IGNORECASE)
VERSION_PATTERN = re.compile(r"\d+\.\d+\.\d+")


def read_pragma(source_code: str) -> str | None:
    match = PRAGMA_PATTERN.search(source_code)
    if not match:
        return None
    return match.group(1).strip()


def select_installable_solc_version(pragma_expression: str | None) -> str | None:
    """Extract a concrete solc version suitable for solc-select install/use.

    Slither needs an installed compiler. This intentionally picks the highest
    explicit x.y.z token present in the pragma rather than trying to solve every
    semver range. For production, replace with a semver resolver backed by the
    solc release list.
    """

    if not pragma_expression:
        return None
    versions = VERSION_PATTERN.findall(pragma_expression)
    if not versions:
        return None
    return sorted(versions, key=lambda value: tuple(int(part) for part in value.split(".")))[-1]
