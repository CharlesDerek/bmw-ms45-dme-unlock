#!/usr/bin/env python3
"""Loopback-only, read-only MS45R1 bridge to an operator-supplied EdiabasTest.

The job names and result names must be validated against the installed PRG on
bench hardware. No write, erase, reset, or security-access request is accepted.
"""
import argparse
import json
import re
import socket
import subprocess
import hashlib
from pathlib import Path

MAGIC = b"MS45R1"
MAX_READ = 4096
BRIDGE_VERSION = "1.2.0"
LABEL = re.compile(r"^[A-Za-z0-9_.-]{1,64}$")
HEX = re.compile(r"^(?:[0-9A-Fa-f]{2}(?: |$))+$")


def load_config(path):
    config = json.loads(Path(path).read_text())
    profile = config.get("profile", "custom")
    if profile == "legacy-ms45":
        config["read_job"] = "speicher_lesen_ascii"
        config["read_result"] = "DATEN"
        config["read_args"] = "{region};{start};{length}"
    elif profile != "custom":
        raise ValueError("unsupported bridge profile")
    if not isinstance(config.get("command"), list) or not config["command"] or not all(isinstance(x, str) and x for x in config["command"]):
        raise ValueError("command must be a nonempty argument array")
    required = ("sgbd", "port", "ifh", "read_job", "read_result") + (("identify_job",) if profile == "custom" else ())
    for key in required:
        if not isinstance(config.get(key), str) or not config[key]:
            raise ValueError(f"missing {key}")
    if "ecu_path" in config and (not isinstance(config["ecu_path"], str) or not config["ecu_path"] or any(c in config["ecu_path"] for c in ";\r\n")):
        raise ValueError("invalid ecu_path")
    for key in ("read_job", "read_result") + (("identify_job",) if profile == "custom" else ()):
        if not LABEL.fullmatch(config[key]):
            raise ValueError(f"invalid {key}")
    if profile == "custom":
        fields = config.get("identity_results")
        if not isinstance(fields, dict) or set(fields) != {"variant", "hardware_reference", "software_reference", "vin"} or not all(isinstance(v, str) and LABEL.fullmatch(v) for v in fields.values()):
            raise ValueError("identity_results must name four exact job results")
        probe = config.get("probe")
        if probe is not None:
            required_probe = {"programming_status_job", "programming_status_result", "diagnostic_protocol_job", "diagnostic_protocol_result"}
            if not isinstance(probe, dict) or set(probe) != required_probe or not all(isinstance(v, str) and LABEL.fullmatch(v) for v in probe.values()):
                raise ValueError("probe must name the status and protocol jobs and results")
    template = config.get("read_args")
    if not isinstance(template, str) or not re.fullmatch(r"[A-Za-z0-9_;{},]+", template) or "{start}" not in template or "{length}" not in template or "{region}" not in template:
        raise ValueError("read_args must contain start, length, and region placeholders")
    return config


def inventory(config, config_path):
    """Return reproducible, redacted tool and adapter information."""
    adapter = config.get("adapter")
    required = ("manufacturer", "model", "interface", "firmware")
    if not isinstance(adapter, dict) or any(not isinstance(adapter.get(k), str) or not adapter[k] for k in required):
        raise ValueError("adapter must provide manufacturer, model, interface, and firmware")
    serial = adapter.get("serial")
    if not isinstance(serial, str) or not serial:
        raise ValueError("adapter must provide serial for one-way inventory hashing")
    version_args = config.get("version_args", ["--version"])
    if not isinstance(version_args, list) or not version_args or not all(isinstance(x, str) and x for x in version_args):
        raise ValueError("version_args must be a nonempty argument array")
    result = subprocess.run(config["command"] + version_args, stdout=subprocess.PIPE,
                            stderr=subprocess.STDOUT, timeout=10, check=False)
    output = result.stdout.decode("utf-8", "replace").strip()
    if result.returncode != 0 or not output or len(output) > 4096:
        raise ValueError("could not capture EdiabasTest version")
    return {
        "schema_version": "ms45.bridge-inventory.v1",
        "bridge_version": BRIDGE_VERSION,
        "bridge_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
        "config_sha256": hashlib.sha256(Path(config_path).read_bytes()).hexdigest(),
        "ediabas_tool_version": output,
        "sgbd": config["sgbd"],
        "adapter": {**{key: adapter[key] for key in required},
                    "serial_sha256": hashlib.sha256(serial.encode()).hexdigest()},
    }


def parse_results(output):
    if len(output) > 65536:
        raise ValueError("job output too large")
    results = {}
    for line in output.decode("utf-8", "strict").splitlines():
        if line.startswith("Error occured:") or line.startswith("Job execution failed:"):
            raise ValueError("job failed")
        if ": " not in line:
            continue
        name, value = line.split(": ", 1)
        if LABEL.fullmatch(name):
            if name in results:
                raise ValueError("duplicate job result")
            results[name] = value.strip()
    if results.get("JOB_STATUS") != "OKAY":
        raise ValueError("job status not OKAY")
    return results


def run_job(config, job, arguments, requested):
    command = config["command"] + [
        "--sgbd=" + config["sgbd"], "--port=" + config["port"],
        "--ifh=" + config["ifh"], "--job=" + job + "#" + arguments + "#" + requested,
    ]
    if config.get("ecu_path"):
        command.append("--cfg=EcuPath=" + config["ecu_path"])
    result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.DEVNULL, timeout=10, check=False)
    if result.returncode != 0:
        raise ValueError("Ediabas job failed")
    return parse_results(result.stdout)


def identify(config):
    if config.get("profile") == "legacy-ms45":
        vin = run_job(config, "aif_lesen", "", "AIF_FG_NR;JOB_STATUS")["AIF_FG_NR"]
        hw = run_job(config, "hardware_referenz_lesen", "", "HARDWARE_REFERENZ;JOB_STATUS")["HARDWARE_REFERENZ"]
        sw = run_job(config, "daten_referenz_lesen", "", "DATEN_REFERENZ;JOB_STATUS")["DATEN_REFERENZ"]
        variant = {"0044560": "MS45.0", "0044570": "MS45.1"}.get(hw)
        if variant is None:
            raise ValueError("unsupported hardware reference")
        values = [variant, hw, sw, vin]
    else:
        fields = config["identity_results"]
        results = run_job(config, config["identify_job"], "", ";".join(fields.values()) + ";JOB_STATUS")
        values = [results[fields[key]] for key in ("variant", "hardware_reference", "software_reference", "vin")]
    if values[0] not in ("MS45.0", "MS45.1") or not all(LABEL.fullmatch(value) for value in values):
        raise ValueError("invalid ECU identity")
    return values


def execute(config, operation, region, start, length):
    if operation in (1, 3) and region == 0 and start == 0 and length == 0:
        variant, hw, sw, vin = identify(config)
        if operation == 1:
            return 0, "|".join((variant, hw, sw, vin)).encode("ascii")
        if config.get("profile") == "legacy-ms45":
            programming_status = run_job(config, "flash_programmier_status_lesen", "", "FLASH_PROGRAMMIER_STATUS;JOB_STATUS")["FLASH_PROGRAMMIER_STATUS"]
            diagnostic_protocol = run_job(config, "DIAGNOSEPROTOKOLL_LESEN", "", "DIAG_PROT_IST;JOB_STATUS")["DIAG_PROT_IST"]
        else:
            probe = config.get("probe")
            if probe is None:
                raise ValueError("custom profile does not configure probe jobs")
            programming_status = run_job(config, probe["programming_status_job"], "", probe["programming_status_result"] + ";JOB_STATUS")[probe["programming_status_result"]]
            diagnostic_protocol = run_job(config, probe["diagnostic_protocol_job"], "", probe["diagnostic_protocol_result"] + ";JOB_STATUS")[probe["diagnostic_protocol_result"]]
        values = (variant, hw, sw, programming_status, diagnostic_protocol, vin)
        if not programming_status.isascii() or not programming_status.isdecimal() or not 0 <= int(programming_status) <= 255:
            raise ValueError("invalid ECU programming status")
        if not all(isinstance(value, str) and value == value.strip() and 1 <= len(value) <= 128 and "|" not in value and value.isascii() and value.isprintable() for value in values):
            raise ValueError("invalid ECU probe result")
        return 0, "|".join(values).encode("ascii")
    if operation != 2:
        return 2, b""
    limits = {1: 0x100000, 2: 0x70000}
    if region not in limits or length < 1 or length > MAX_READ or start + length > limits[region]:
        return 1, b""
    data = bytearray()
    chunk_limit = 254 if config.get("profile") == "legacy-ms45" else MAX_READ
    while len(data) < length:
        chunk = min(chunk_limit, length - len(data))
        segment = {1: "ROMX", 2: "LAR"}[region] if config.get("profile") == "legacy-ms45" else region
        arguments = config["read_args"].format(start=start + len(data), length=chunk, region=segment)
        result = run_job(config, config["read_job"], arguments, config["read_result"] + ";JOB_STATUS")
        value = result[config["read_result"]]
        if not HEX.fullmatch(value):
            raise ValueError("invalid memory result encoding")
        block = bytes.fromhex(value)
        if len(block) != chunk:
            raise ValueError("short memory result")
        data.extend(block)
    return 0, bytes(data)


def receive_exact(connection, count):
    data = bytearray()
    while len(data) < count:
        block = connection.recv(count - len(data))
        if not block:
            return None
        data.extend(block)
    return bytes(data)


def serve(config, bind):
    host, port = bind.rsplit(":", 1)
    if host not in ("127.0.0.1", "localhost"):
        raise ValueError("bridge must bind to loopback")
    with socket.create_server(("127.0.0.1", int(port))) as server:
        while True:
            connection, _ = server.accept()
            with connection:
                connection.settimeout(15)
                try:
                    while True:
                        request = receive_exact(connection, 22)
                        if request is None or request[:6] != MAGIC:
                            break
                        nonce = request[6:14]
                        try:
                            status, payload = execute(config, request[14], request[15], int.from_bytes(request[16:20], "big"), int.from_bytes(request[20:22], "big"))
                        except (KeyError, ValueError, UnicodeError, subprocess.TimeoutExpired):
                            status, payload = 2, b""
                        connection.sendall(MAGIC + nonce + bytes([status]) + len(payload).to_bytes(2, "big") + payload)
                except (TimeoutError, OSError):
                    pass


if __name__ == "__main__":
    parser = argparse.ArgumentParser()
    parser.add_argument("--config", required=True)
    parser.add_argument("--bind", default="127.0.0.1:4581")
    parser.add_argument("--inventory", action="store_true",
                        help="print redacted adapter/tool inventory and exit")
    parser.add_argument("--version", action="version", version=BRIDGE_VERSION)
    args = parser.parse_args()
    config = load_config(args.config)
    if args.inventory:
        print(json.dumps(inventory(config, args.config), sort_keys=True))
    else:
        serve(config, args.bind)
