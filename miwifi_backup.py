#!/usr/bin/env python3
"""Convert stock MiWiFi backup archives to editable JSON and back."""

import argparse
import getpass
import io
import json
import os
from pathlib import Path
import re
import sys
import tarfile
import tempfile
import time

from miwifi_cipher import decrypt, encrypt


DESCRIPTION_NAME = "cfg_backup.des"
CONFIG_NAME = "cfg_backup.mbu"
BACKUP_NAMES = {DESCRIPTION_NAME, CONFIG_NAME}


class BackupError(ValueError):
    """A user-facing error that omits backup values."""


def router_seed(serial_number, lan_mac):
    prefix = serial_number.strip()[:5]
    if len(prefix) != 5 or not prefix.isascii():
        raise BackupError("The router serial number must start with five ASCII characters.")
    mac = lan_mac.strip().lower()
    if not re.fullmatch(r"[0-9a-f]{12}|(?:[0-9a-f]{2}:){5}[0-9a-f]{2}", mac):
        raise BackupError("Enter the LAN MAC as 12 hexadecimal digits, with or without colons.")
    return (prefix + mac.replace(":", "")).encode("ascii")


def unique_object(pairs):
    result = dict(pairs)
    if len(result) != len(pairs):
        raise ValueError("duplicate object key")
    return result


def reject_nonfinite(_value):
    raise ValueError("non-finite number")


def read_json(data, label, kind):
    try:
        value = json.loads(
            data.decode("utf-8"),
            object_pairs_hook=unique_object,
            parse_constant=reject_nonfinite,
        )
    except (ValueError, RecursionError) as exc:
        raise BackupError(f"{label} is invalid UTF-8 JSON.") from exc
    if not isinstance(value, kind):
        shape = "array" if kind is list else "object"
        raise BackupError(f"{label} must be a JSON {shape}.")
    return value


def write_json(value, *, editable=False):
    try:
        if editable:
            text = json.dumps(value, ensure_ascii=False, allow_nan=False, indent=2) + "\n"
        else:
            text = json.dumps(value, ensure_ascii=False, allow_nan=False, separators=(",", ":"))
        return text.encode("utf-8")
    except (ValueError, RecursionError) as exc:
        raise BackupError("The backup contains values that cannot be written as UTF-8 JSON.") from exc


def read_backup(path):
    contents = {}
    try:
        with tarfile.open(path, "r:gz") as archive:
            for member in archive:
                if member.name not in BACKUP_NAMES or not member.isreg() or member.name in contents:
                    raise BackupError("Expected one regular file for each stock backup entry.")
                with archive.extractfile(member) as entry:
                    contents[member.name] = entry.read()
    except (tarfile.TarError, EOFError) as exc:
        raise BackupError("The backup is not a readable gzip-compressed tar archive.") from exc
    if contents.keys() != BACKUP_NAMES:
        raise BackupError("The archive must contain cfg_backup.des and cfg_backup.mbu.")
    return contents


def write_backup(output, description, config):
    with tarfile.open(name="", fileobj=output, mode="w:gz", format=tarfile.GNU_FORMAT) as archive:
        timestamp = int(time.time())
        for name, data in ((DESCRIPTION_NAME, description), (CONFIG_NAME, config)):
            member = tarfile.TarInfo(name)
            member.size = len(data)
            member.mtime = timestamp
            member.uname = member.gname = "root"
            archive.addfile(member, io.BytesIO(data))


def decrypt_backup(path, output, seed):
    contents = read_backup(path)
    description = read_json(contents[DESCRIPTION_NAME], DESCRIPTION_NAME, list)
    try:
        plaintext = decrypt(contents[CONFIG_NAME], seed)
        config = read_json(plaintext, CONFIG_NAME, dict)
    except ValueError as exc:
        raise BackupError("Could not decrypt the configuration. Check the router serial number and LAN MAC.") from exc
    output.write(write_json({"description": description, "config": config}, editable=True))


def encrypt_backup(path, output, seed):
    envelope = read_json(path.read_bytes(), "Editable backup", dict)
    if envelope.keys() != {"description", "config"}:
        raise BackupError("The editable backup must have description and config fields.")
    if not isinstance(envelope["description"], list) or not isinstance(envelope["config"], dict):
        raise BackupError("The description must be an array and the config must be an object.")
    description = write_json(envelope["description"])
    encrypted_config = encrypt(write_json(envelope["config"]), seed)
    write_backup(output, description, encrypted_config)


def atomic_output(path, action):
    temp_path = None
    try:
        with tempfile.NamedTemporaryFile(mode="w+b", dir=path.parent, prefix=".miwifi-", delete=False) as output:
            temp_path = Path(output.name)
            action(output)
            output.flush()
            os.fsync(output.fileno())
        # Link the private temporary file into place without replacing a concurrent writer's output.
        os.link(temp_path, path)
    finally:
        if temp_path is not None:
            temp_path.unlink()


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    commands = parser.add_subparsers(dest="command", required=True)
    decrypt_parser = commands.add_parser("decrypt", help="Convert a stock .tar.gz backup to editable JSON.")
    encrypt_parser = commands.add_parser("encrypt", help="Convert edited JSON to a stock-format .tar.gz backup.")
    for command, source_help, target_help in (
        (decrypt_parser, "stock backup archive", "new editable JSON file"),
        (encrypt_parser, "editable JSON file", "new stock-format backup archive"),
    ):
        command.add_argument("source", type=Path, help=source_help)
        command.add_argument("output", type=Path, help=target_help)
        command.add_argument("--sn", help="router serial number (prompted if omitted)")
        command.add_argument("--lan-mac", help="router LAN MAC address (prompted if omitted)")
    args = parser.parse_args(argv)
    if (args.sn is None or args.lan_mac is None) and not sys.stdin.isatty():
        parser.error("Pass --sn and --lan-mac when running without an interactive terminal.")
    action = decrypt_backup if args.command == "decrypt" else encrypt_backup
    try:
        if os.path.lexists(args.output):
            raise BackupError("The output path already exists. Choose a new path.")
        serial_number = args.sn if args.sn is not None else getpass.getpass("Router serial number: ")
        lan_mac = args.lan_mac if args.lan_mac is not None else getpass.getpass("Router LAN MAC: ")
        seed = router_seed(serial_number, lan_mac)
        atomic_output(args.output, lambda output: action(args.source, output, seed))
    except (EOFError, KeyboardInterrupt):
        parser.exit(1, f"{parser.prog}: Backup conversion canceled.\n")
    except BackupError as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    except OSError as exc:
        parser.exit(1, f"{parser.prog}: {exc}\n")
    return 0


if __name__ == "__main__":
    sys.exit(main())
