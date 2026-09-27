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
from pathlib import Path

MAGIC = b"MS45R1"
MAX_READ = 4096
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
    template = config.get("read_args")
    if not isinstance(template, str) or not re.fullmatch(r"[A-Za-z0-9_;{},]+", template) or "{start}" not in template or "{length}" not in template or "{region}" not in template:
        raise ValueError("read_args must contain start, length, and region placeholders")
    return config


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


def execute(config, operation, region, start, length):
    if operation == 1 and region == 0 and start == 0 and length == 0:
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
    args = parser.parse_args()
    serve(load_config(args.config), args.bind)
