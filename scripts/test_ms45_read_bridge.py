import unittest
import tempfile
import json
import hashlib
from pathlib import Path
from unittest.mock import patch

import ms45_read_bridge as bridge


CONFIG = {
    "command": ["EdiabasTest.exe"], "sgbd": "ms450ds0.prg", "port": "COM4",
    "ifh": "STD:OBD", "identify_job": "identifikation",
    "identity_results": {"variant": "VARIANTE", "hardware_reference": "HW_REF", "software_reference": "SW_REF", "vin": "VIN"},
    "read_job": "speicher_lesen_ascii", "read_result": "MEMORY",
    "read_args": "{region};{start};{length}",
    "probe": {"programming_status_job": "program_status", "programming_status_result": "PROGRAM_STATUS", "diagnostic_protocol_job": "diag_protocol", "diagnostic_protocol_result": "DIAG_PROTOCOL"},
}


class BridgeTests(unittest.TestCase):
    def test_inventory_hashes_serial_and_captures_versions(self):
        with tempfile.TemporaryDirectory() as directory:
            config_path = Path(directory) / "config.json"
            config = {**CONFIG, "adapter": {"manufacturer": "TestCo", "model": "ReadOnly", "interface": "USB", "firmware": "1.2", "serial": "PRIVATE123"}}
            config_path.write_text(json.dumps(config))
            completed = type("Completed", (), {"returncode": 0, "stdout": b"EdiabasTest 1.2.3\n"})()
            with patch.object(bridge.subprocess, "run", return_value=completed):
                result = bridge.inventory(config, config_path)
        self.assertEqual(result["bridge_version"], bridge.BRIDGE_VERSION)
        self.assertEqual(result["ediabas_tool_version"], "EdiabasTest 1.2.3")
        self.assertEqual(result["adapter"]["serial_sha256"], hashlib.sha256(b"PRIVATE123").hexdigest())
        self.assertNotIn("serial", result["adapter"])

    def test_identity_and_exact_read(self):
        def fake_job(_config, job, arguments, _requested):
            if job == "identifikation":
                return {"VARIANTE": "MS45.1", "HW_REF": "HW1", "SW_REF": "SW1", "VIN": "TESTVIN"}
            self.assertEqual(arguments, "1;10;2")
            return {"MEMORY": "AA BB"}

        with patch.object(bridge, "run_job", side_effect=fake_job):
            self.assertEqual(bridge.execute(CONFIG, 1, 0, 0, 0), (0, b"MS45.1|HW1|SW1|TESTVIN"))
            self.assertEqual(bridge.execute(CONFIG, 2, 1, 10, 2), (0, b"\xaa\xbb"))

    def test_probe_reads_metadata_only(self):
        calls = []
        def fake_job(_config, job, _arguments, _requested):
            calls.append(job)
            return {
                "identifikation": {"VARIANTE": "MS45.1", "HW_REF": "HW1", "SW_REF": "SW1", "VIN": "TESTVIN"},
                "program_status": {"PROGRAM_STATUS": "programmed"},
                "diag_protocol": {"DIAG_PROTOCOL": "BMW-FAST"},
            }[job]
        with patch.object(bridge, "run_job", side_effect=fake_job):
            result = bridge.execute(CONFIG, 3, 0, 0, 0)
        self.assertEqual(result, (0, b"MS45.1|HW1|SW1|programmed|BMW-FAST|TESTVIN"))
        self.assertEqual(calls, ["identifikation", "program_status", "diag_protocol"])

    def test_rejects_write_and_bad_ranges_without_invoking_job(self):
        with patch.object(bridge, "run_job") as job:
            self.assertEqual(bridge.execute(CONFIG, 3, 1, 0, 2), (2, b""))
            self.assertEqual(bridge.execute(CONFIG, 2, 1, 0, 4097), (1, b""))
            job.assert_not_called()

    def test_job_output_requires_success_and_unique_results(self):
        good = b"JOB: read\nDATASET: 1\nJOB_STATUS: OKAY\nMEMORY: AA BB \n"
        self.assertEqual(bridge.parse_results(good)["MEMORY"], "AA BB")
        with self.assertRaises(ValueError):
            bridge.parse_results(good + b"MEMORY: FF\n")
        with self.assertRaises(ValueError):
            bridge.parse_results(b"JOB_STATUS: ERROR\nMEMORY: AA\n")

    def test_short_read_fails(self):
        with patch.object(bridge, "run_job", return_value={"MEMORY": "AA"}):
            with self.assertRaises(ValueError):
                bridge.execute(CONFIG, 2, 1, 0, 2)

    def test_subprocess_job_fixture(self):
        with tempfile.TemporaryDirectory() as directory:
            runner = Path(directory) / "fake_ediabas.py"
            runner.write_text("#!/usr/bin/env python3\nimport sys\nassert any(x.startswith('--job=speicher_lesen_ascii#1;10;2#') for x in sys.argv)\nprint('DATASET: 1\\nJOB_STATUS: OKAY\\nMEMORY: AA BB')\n")
            runner.chmod(0o700)
            config = {**CONFIG, "command": [str(runner)]}
            self.assertEqual(bridge.execute(config, 2, 1, 10, 2), (0, b"\xaa\xbb"))

    def test_legacy_profile_uses_original_jobs_and_254_byte_reads(self):
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / "config.json"
            path.write_text(json.dumps({"profile": "legacy-ms45", "command": ["EdiabasTest.exe"], "sgbd": "ms450ds0.prg", "port": "COM4", "ifh": "STD:OBD"}))
            config = bridge.load_config(path)
        calls = []
        def fake_job(_config, job, arguments, _requested):
            calls.append((job, arguments))
            identity = {"aif_lesen": {"AIF_FG_NR": "TESTVIN"}, "hardware_referenz_lesen": {"HARDWARE_REFERENZ": "0044570"}, "daten_referenz_lesen": {"DATEN_REFERENZ": "SW1"}}
            return identity[job] if job in identity else {"DATEN": " ".join(["AB"] * int(arguments.split(";")[2]))}
        with patch.object(bridge, "run_job", side_effect=fake_job):
            self.assertEqual(bridge.execute(config, 1, 0, 0, 0), (0, b"MS45.1|0044570|SW1|TESTVIN"))
            self.assertEqual(bridge.execute(config, 2, 1, 0, 300), (0, b"\xab" * 300))
        self.assertEqual(calls[-2:], [("speicher_lesen_ascii", "ROMX;0;254"), ("speicher_lesen_ascii", "ROMX;254;46")])


if __name__ == "__main__":
    unittest.main()
