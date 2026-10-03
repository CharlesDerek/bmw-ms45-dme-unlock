#!/usr/bin/env python3
"""Create a deterministic release archive and its SHA-256 checksum."""

from __future__ import annotations

import argparse
import hashlib
from pathlib import Path
import re
import stat
import zipfile


VERSION_RE = re.compile(r"^[0-9]+\.[0-9]+\.[0-9]+(?:[-+][0-9A-Za-z.-]+)?$")
ZIP_TIMESTAMP = (1980, 1, 1, 0, 0, 0)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--version", required=True, help="release version without a leading v")
    parser.add_argument("--target", required=True, help="Rust target triple")
    parser.add_argument("--binary-dir", required=True, type=Path)
    parser.add_argument("--sbom-dir", required=True, type=Path)
    parser.add_argument("--output-dir", required=True, type=Path)
    parser.add_argument("--project-root", type=Path, default=Path.cwd())
    return parser.parse_args()


def zip_entry(archive: zipfile.ZipFile, name: str, source: Path, executable: bool) -> None:
    info = zipfile.ZipInfo(name, ZIP_TIMESTAMP)
    info.create_system = 3
    mode = stat.S_IFREG | (0o755 if executable else 0o644)
    info.external_attr = mode << 16
    info.compress_type = zipfile.ZIP_DEFLATED
    archive.writestr(info, source.read_bytes(), compresslevel=9)


def package(
    version: str,
    target: str,
    binary_dir: Path,
    sbom_dir: Path,
    output_dir: Path,
    project_root: Path,
) -> tuple[Path, Path]:
    if not VERSION_RE.fullmatch(version):
        raise ValueError(f"invalid release version: {version!r}")

    suffix = ".exe" if "windows" in target else ""
    root = f"bmw-ms45-dme-unlock-{version}-{target}"
    files = [
        (f"{root}/LICENSE", project_root / "LICENSE", False),
        (f"{root}/README.md", project_root / "README.md", False),
        (f"{root}/bin/ms45{suffix}", binary_dir / f"ms45{suffix}", True),
        (f"{root}/bin/ms45-gui{suffix}", binary_dir / f"ms45-gui{suffix}", True),
        (f"{root}/sbom/ms45.cdx.json", sbom_dir / "ms45.cdx.json", False),
        (f"{root}/sbom/ms45-gui.cdx.json", sbom_dir / "ms45-gui.cdx.json", False),
    ]
    missing = [str(source) for _, source, _ in files if not source.is_file()]
    if missing:
        raise FileNotFoundError("missing release input(s): " + ", ".join(missing))

    output_dir.mkdir(parents=True, exist_ok=True)
    archive_path = output_dir / f"{root}.zip"
    with zipfile.ZipFile(archive_path, "w") as archive:
        for name, source, executable in sorted(files):
            zip_entry(archive, name, source, executable)

    digest = hashlib.sha256(archive_path.read_bytes()).hexdigest()
    checksum_path = archive_path.with_suffix(archive_path.suffix + ".sha256")
    checksum_path.write_text(f"{digest}  {archive_path.name}\n", encoding="ascii", newline="\n")
    return archive_path, checksum_path


def main() -> None:
    args = parse_args()
    archive, checksum = package(
        args.version,
        args.target,
        args.binary_dir,
        args.sbom_dir,
        args.output_dir,
        args.project_root,
    )
    print(archive)
    print(checksum)


if __name__ == "__main__":
    main()
