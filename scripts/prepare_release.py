#!/usr/bin/env python3
"""Build and validate deterministic GovHawk release assets."""

from __future__ import annotations

import argparse
import ast
import hashlib
import json
import re
import stat
import time
import unicodedata
import zipfile
from pathlib import Path, PurePosixPath

PROJECT_NAME = "GovHawk: AWS GovCloud Efficiency Analyzer"
PROJECT_SLUG = "AWS-GovHawk-Efficiency-Analyzer"
REPOSITORY_URL = "https://github.com/fusiontechstrategies/AWS-GovHawk-Efficiency-Analyzer"
RUNTIME_SOURCE = "AWS_GovCloud_Analyzer.py"
STABLE_VERSION = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+$")
COMMIT_ID = re.compile(r"^[0-9a-f]{40}$")
PINNED_REQUIREMENT = re.compile(r"^([A-Za-z0-9][A-Za-z0-9._-]*)==([^\s;]+)$")
WINDOWS_RESERVED_NAMES = {
    "CON",
    "PRN",
    "AUX",
    "NUL",
    *(f"COM{index}" for index in range(1, 10)),
    *(f"LPT{index}" for index in range(1, 10)),
}

PACKAGE_FILES = (
    "AWS_GovCloud_Analyzer.py",
    "CHANGELOG.md",
    "CODE_OF_CONDUCT.md",
    "CONTRIBUTING.md",
    "IAM_PERMISSIONS.md",
    "LICENSE",
    "PUBLIC_RELEASE_CHECKLIST.md",
    "README.md",
    "RELEASING.md",
    "SECURITY.md",
    "SUPPORT.md",
    "TESTING.md",
    "pyproject.toml",
    "requirements-dev.txt",
    "requirements.txt",
    "scripts/prepare_release.py",
    "tests/test_analyzer.py",
    "tests/test_release_assets.py",
)


class ReleaseError(RuntimeError):
    """Release input, package content, or output violates the contract."""


def require(condition: bool, message: str) -> None:
    if not condition:
        raise ReleaseError(message)


def sha256_bytes(value: bytes) -> str:
    return hashlib.sha256(value).hexdigest()


def sha256_file(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def read_runtime_version(path: Path) -> str:
    try:
        tree = ast.parse(path.read_text(encoding="utf-8"), filename=str(path))
    except (OSError, SyntaxError, UnicodeError) as error:
        raise ReleaseError(f"Unable to parse runtime identity from {path}") from error
    versions: list[str] = []
    for node in tree.body:
        if not isinstance(node, ast.Assign) or len(node.targets) != 1:
            continue
        target = node.targets[0]
        if not isinstance(target, ast.Name) or target.id != "VERSION":
            continue
        require(
            isinstance(node.value, ast.Constant) and isinstance(node.value.value, str),
            "Runtime VERSION must be a string constant",
        )
        versions.append(node.value.value)
    require(len(versions) == 1, "Runtime must define exactly one VERSION string")
    require(STABLE_VERSION.fullmatch(versions[0]) is not None, "Runtime VERSION must be stable X.Y.Z")
    return versions[0]


def read_release_date(project_root: Path, version: str) -> str:
    changelog = (project_root / "CHANGELOG.md").read_text(encoding="utf-8")
    matches = re.findall(rf"(?m)^## \[{re.escape(version)}\] - ([0-9]{{4}}-[0-9]{{2}}-[0-9]{{2}})$", changelog)
    require(len(matches) == 1, "Changelog must contain one exact stable release heading")
    return matches[0]


def normalize_distribution_name(name: str) -> str:
    return re.sub(r"[-_.]+", "-", name).lower()


def parse_runtime_dependencies(project_root: Path) -> list[dict[str, str]]:
    dependencies: list[dict[str, str]] = []
    normalized_names: set[str] = set()
    for raw_line in (project_root / "requirements.txt").read_text(encoding="utf-8").splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#"):
            continue
        match = PINNED_REQUIREMENT.fullmatch(line)
        require(match is not None, f"Runtime requirement is not an exact package pin: {line!r}")
        name, version = match.groups()
        normalized = normalize_distribution_name(name)
        require(normalized not in normalized_names, f"Duplicate runtime dependency: {name}")
        normalized_names.add(normalized)
        dependencies.append({"name": name, "normalized_name": normalized, "version": version})
    require(bool(dependencies), "At least one runtime dependency is required")
    return sorted(dependencies, key=lambda item: item["normalized_name"])


def validate_relative_name(name: str) -> tuple[str, ...]:
    require("\\" not in name, f"Package path uses a backslash: {name!r}")
    require(not name.startswith("/"), f"Package path is absolute: {name!r}")
    require(re.match(r"^[A-Za-z]:", name) is None, f"Package path uses a drive: {name!r}")
    parts = tuple(name.split("/"))
    require(bool(parts) and all(part not in {"", ".", ".."} for part in parts), f"Unsafe path: {name!r}")
    require(tuple(PurePosixPath(*parts).parts) == parts, f"Noncanonical path: {name!r}")
    for part in parts:
        require(not part.endswith((" ", ".")), f"Nonportable path: {name!r}")
        require(
            all(ord(character) >= 32 and ord(character) != 127 for character in part),
            f"Path contains a control character: {name!r}",
        )
        require(
            part.split(".", 1)[0].upper() not in WINDOWS_RESERVED_NAMES,
            f"Path uses a reserved Windows name: {name!r}",
        )
    return parts


def validate_package_files(project_root: Path) -> dict[str, bytes]:
    files: dict[str, bytes] = {}
    portable_names: set[str] = set()
    for relative_name in PACKAGE_FILES:
        parts = validate_relative_name(relative_name)
        portable = unicodedata.normalize("NFC", relative_name).casefold()
        require(portable not in portable_names, f"Package contains a nonportable duplicate: {relative_name!r}")
        portable_names.add(portable)
        source = project_root.joinpath(*parts)
        require(source.is_file() and not source.is_symlink(), f"Required regular file is missing: {relative_name}")
        files[relative_name] = source.read_bytes()
    return files


def expected_timestamp(source_date_epoch: int) -> tuple[int, int, int, int, int, int]:
    parts = list(time.gmtime(source_date_epoch)[:6])
    parts[5] -= parts[5] % 2
    return (parts[0], parts[1], parts[2], parts[3], parts[4], parts[5])


def build_zip(path: Path, version: str, files: dict[str, bytes], source_date_epoch: int) -> None:
    prefix = f"{PROJECT_SLUG}-v{version}"
    timestamp = expected_timestamp(source_date_epoch)
    try:
        with zipfile.ZipFile(path, mode="x", compression=zipfile.ZIP_STORED, strict_timestamps=True) as archive:
            for relative_name in sorted(files):
                member_name = f"{prefix}/{relative_name}"
                member = zipfile.ZipInfo(member_name, timestamp)
                member.create_system = 3
                member.compress_type = zipfile.ZIP_STORED
                member.external_attr = (stat.S_IFREG | 0o644) << 16
                member.flag_bits = 0
                member.extra = b""
                member.comment = b""
                archive.writestr(member, files[relative_name])
    except FileExistsError as error:
        raise ReleaseError(f"Refusing to replace release output: {path}") from error


def inspect_zip(path: Path, version: str, files: dict[str, bytes], source_date_epoch: int) -> list[dict[str, object]]:
    prefix = f"{PROJECT_SLUG}-v{version}"
    expected_names = [f"{prefix}/{name}" for name in sorted(files)]
    expected_time = expected_timestamp(source_date_epoch)
    records: list[dict[str, object]] = []
    with zipfile.ZipFile(path) as archive:
        require(archive.comment == b"", "ZIP has a noncanonical archive comment")
        members = archive.infolist()
        require([member.filename for member in members] == expected_names, "ZIP member set or order differs")
        for member, relative_name in zip(members, sorted(files), strict=True):
            validate_relative_name(member.filename)
            require(member.date_time == expected_time, f"ZIP timestamp differs: {member.filename!r}")
            require(member.compress_type == zipfile.ZIP_STORED, f"ZIP member is not stored: {member.filename!r}")
            require(member.create_system == 3, f"ZIP creator system differs: {member.filename!r}")
            require(member.flag_bits & 1 == 0, f"ZIP member is encrypted: {member.filename!r}")
            require(
                member.extra == b"" and member.comment == b"", f"ZIP member has extra metadata: {member.filename!r}"
            )
            mode = member.external_attr >> 16
            require(
                stat.S_ISREG(mode) and stat.S_IMODE(mode) == 0o644,
                f"ZIP member has a noncanonical mode: {member.filename!r}",
            )
            value = archive.read(member)
            require(value == files[relative_name], f"ZIP member bytes differ: {member.filename!r}")
            records.append(
                {
                    "bytes": len(value),
                    "name": member.filename,
                    "sha256": sha256_bytes(value),
                    "type": "file",
                }
            )
    return records


def build_spdx(
    version: str,
    release_date: str,
    runtime_digest: str,
    dependencies: list[dict[str, str]],
) -> bytes:
    root_id = "SPDXRef-Package"
    packages: list[dict[str, object]] = [
        {
            "SPDXID": root_id,
            "checksums": [{"algorithm": "SHA256", "checksumValue": runtime_digest}],
            "copyrightText": "NOASSERTION",
            "downloadLocation": "NOASSERTION",
            "externalRefs": [
                {
                    "referenceCategory": "PACKAGE-MANAGER",
                    "referenceLocator": f"pkg:github/fusiontechstrategies/AWS-GovHawk-Efficiency-Analyzer@{version}",
                    "referenceType": "purl",
                }
            ],
            "filesAnalyzed": False,
            "licenseConcluded": "Apache-2.0",
            "licenseDeclared": "Apache-2.0",
            "name": PROJECT_NAME,
            "supplier": "Organization: Fusion Technology Strategies",
            "versionInfo": version,
        }
    ]
    relationships: list[dict[str, str]] = [
        {
            "spdxElementId": "SPDXRef-DOCUMENT",
            "relationshipType": "DESCRIBES",
            "relatedSpdxElement": root_id,
        }
    ]
    for index, dependency in enumerate(dependencies, start=1):
        package_id = f"SPDXRef-Dependency-{index:03d}-{dependency['normalized_name']}"
        packages.append(
            {
                "SPDXID": package_id,
                "copyrightText": "NOASSERTION",
                "downloadLocation": "NOASSERTION",
                "externalRefs": [
                    {
                        "referenceCategory": "PACKAGE-MANAGER",
                        "referenceLocator": f"pkg:pypi/{dependency['normalized_name']}@{dependency['version']}",
                        "referenceType": "purl",
                    }
                ],
                "filesAnalyzed": False,
                "licenseConcluded": "NOASSERTION",
                "licenseDeclared": "NOASSERTION",
                "name": dependency["name"],
                "supplier": "NOASSERTION",
                "versionInfo": dependency["version"],
            }
        )
        relationships.append(
            {
                "spdxElementId": root_id,
                "relationshipType": "DEPENDS_ON",
                "relatedSpdxElement": package_id,
            }
        )
    document = {
        "SPDXID": "SPDXRef-DOCUMENT",
        "creationInfo": {
            "created": f"{release_date}T00:00:00Z",
            "creators": [
                "Organization: Fusion Technology Strategies",
                "Tool: scripts/prepare_release.py",
            ],
        },
        "dataLicense": "CC0-1.0",
        "documentNamespace": f"{REPOSITORY_URL}/releases/tag/v{version}#spdx-{runtime_digest}",
        "name": f"{PROJECT_SLUG}-v{version}",
        "packages": packages,
        "relationships": relationships,
        "spdxVersion": "SPDX-2.3",
    }
    return (json.dumps(document, indent=2, sort_keys=True) + "\n").encode("utf-8")


def expected_asset_names(version: str) -> tuple[str, ...]:
    stem = f"{PROJECT_SLUG}-v{version}"
    return (
        f"{stem}.py",
        f"{stem}.zip",
        f"{stem}.spdx.json",
        "SHA256SUMS.txt",
        "release-evidence.json",
    )


def write_exclusive(path: Path, value: bytes) -> None:
    try:
        with path.open("xb") as handle:
            handle.write(value)
    except FileExistsError as error:
        raise ReleaseError(f"Refusing to replace release output: {path}") from error


def prepare_release(
    project_root: Path,
    output_directory: Path,
    version: str,
    tag: str,
    source_commit: str,
    source_date_epoch: int,
) -> tuple[Path, ...]:
    project_root = project_root.resolve(strict=True)
    output_directory = output_directory.resolve(strict=False)
    require(STABLE_VERSION.fullmatch(version) is not None, "Release version must be stable X.Y.Z")
    require(tag == f"v{version}", f"Release tag {tag!r} does not match v{version}")
    require(COMMIT_ID.fullmatch(source_commit) is not None, "Source commit must be 40 lowercase hex")
    require(315532800 <= source_date_epoch <= 0xFFFFFFFF, "SOURCE_DATE_EPOCH is outside release range")
    require(read_runtime_version(project_root / RUNTIME_SOURCE) == version, "Runtime and requested versions differ")
    release_date = read_release_date(project_root, version)
    notes_path = project_root / ".github" / "release-notes" / f"v{version}.md"
    require(notes_path.is_file() and not notes_path.is_symlink(), f"Release notes are missing: {notes_path}")
    require(not output_directory.exists(), "Release output directory already exists")
    require(output_directory.parent.is_dir(), "Release output parent does not exist")

    files = validate_package_files(project_root)
    dependencies = parse_runtime_dependencies(project_root)
    runtime_value = files[RUNTIME_SOURCE]
    asset_names = expected_asset_names(version)
    output_directory.mkdir()
    runtime_asset = output_directory / asset_names[0]
    zip_asset = output_directory / asset_names[1]
    spdx_asset = output_directory / asset_names[2]
    checksums_asset = output_directory / asset_names[3]
    evidence_asset = output_directory / asset_names[4]

    write_exclusive(runtime_asset, runtime_value)
    build_zip(zip_asset, version, files, source_date_epoch)
    zip_members = inspect_zip(zip_asset, version, files, source_date_epoch)
    write_exclusive(
        spdx_asset,
        build_spdx(version, release_date, sha256_bytes(runtime_value), dependencies),
    )

    primary_assets = (runtime_asset, zip_asset, spdx_asset)
    checksum_lines = [f"{sha256_file(path)}  {path.name}" for path in primary_assets]
    write_exclusive(checksums_asset, ("\n".join(checksum_lines) + "\n").encode("ascii"))

    evidence_inputs = (*primary_assets, checksums_asset)
    evidence = {
        "artifacts": [
            {"bytes": path.stat().st_size, "name": path.name, "sha256": sha256_file(path)} for path in evidence_inputs
        ],
        "dependencies": dependencies,
        "expected_release_assets": list(asset_names),
        "project": PROJECT_NAME,
        "release_date": release_date,
        "repository": REPOSITORY_URL,
        "runtime_source_sha256": sha256_bytes(runtime_value),
        "schema_version": 1,
        "source_commit": source_commit,
        "source_date_epoch": source_date_epoch,
        "tag": tag,
        "version": version,
        "zip_members": zip_members,
    }
    write_exclusive(evidence_asset, (json.dumps(evidence, indent=2, sort_keys=True) + "\n").encode("utf-8"))

    outputs = tuple(output_directory / name for name in asset_names)
    require(all(path.is_file() and not path.is_symlink() for path in outputs), "Release assets are incomplete")
    require({path.name for path in output_directory.iterdir()} == set(asset_names), "Unexpected release asset")
    return outputs


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True)
    parser.add_argument("--tag", required=True)
    parser.add_argument("--source-commit", required=True)
    parser.add_argument("--source-date-epoch", required=True, type=int)
    parser.add_argument("--output-directory", type=Path, required=True)
    return parser


def main() -> int:
    arguments = build_parser().parse_args()
    project_root = Path(__file__).resolve().parents[1]
    try:
        outputs = prepare_release(
            project_root,
            arguments.output_directory,
            arguments.version,
            arguments.tag,
            arguments.source_commit,
            arguments.source_date_epoch,
        )
    except (OSError, ReleaseError, UnicodeError, ValueError, zipfile.BadZipFile) as error:
        raise SystemExit(f"Release preparation failed: {error}") from error
    for output in outputs:
        print(f"{sha256_file(output)}  {output.name}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
