import hashlib
from pathlib import Path
import tempfile
import unittest
import zipfile

from package import package


class PackageTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        (self.root / "LICENSE").write_text("license\n")
        (self.root / "README.md").write_text("readme\n")
        self.bin_dir = self.root / "bin"
        self.sbom_dir = self.root / "sbom"
        self.bin_dir.mkdir()
        self.sbom_dir.mkdir()
        (self.bin_dir / "ms45").write_bytes(b"cli")
        (self.bin_dir / "ms45-gui").write_bytes(b"gui")
        (self.sbom_dir / "ms45.cdx.json").write_text('{"bomFormat":"CycloneDX"}\n')
        (self.sbom_dir / "ms45-gui.cdx.json").write_text('{"bomFormat":"CycloneDX"}\n')

    def tearDown(self):
        self.temp.cleanup()

    def test_archive_is_reproducible_and_checksum_matches(self):
        first, checksum = package(
            "1.2.3", "x86_64-unknown-linux-gnu", self.bin_dir, self.sbom_dir,
            self.root / "first", self.root,
        )
        for path in self.bin_dir.iterdir():
            path.touch()
        second, _ = package(
            "1.2.3", "x86_64-unknown-linux-gnu", self.bin_dir, self.sbom_dir,
            self.root / "second", self.root,
        )
        self.assertEqual(first.read_bytes(), second.read_bytes())
        expected = hashlib.sha256(first.read_bytes()).hexdigest()
        self.assertEqual(checksum.read_text(), f"{expected}  {first.name}\n")

        with zipfile.ZipFile(first) as archive:
            infos = archive.infolist()
            self.assertEqual([item.filename for item in infos], sorted(item.filename for item in infos))
            self.assertTrue(all(item.date_time == (1980, 1, 1, 0, 0, 0) for item in infos))
            self.assertEqual(len(infos), 6)

    def test_windows_executable_names_are_required(self):
        with self.assertRaisesRegex(FileNotFoundError, r"ms45\.exe"):
            package(
                "1.2.3", "x86_64-pc-windows-msvc", self.bin_dir, self.sbom_dir,
                self.root / "windows", self.root,
            )

    def test_rejects_unsafe_version(self):
        with self.assertRaisesRegex(ValueError, "invalid release version"):
            package(
                "../bad", "x86_64-unknown-linux-gnu", self.bin_dir, self.sbom_dir,
                self.root / "bad", self.root,
            )

if __name__ == "__main__":
    unittest.main()
