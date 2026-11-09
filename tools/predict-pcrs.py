#!/usr/bin/env python3
# stage0's PCR replay file -- the root of the verification path.
#
# Given a stage0 build/release directory, write the events that UEFI firmware and stage0 extend
# from TPM reset to stage0's payload handoff (before ExitBootServices), as a pcr-replay/v1 file
# (format and verifier: workspace tools/pcr-replay). Each event carries a derivation from the
# release artifacts AND the digests computed here, independently, so a replay cross-checks both.
# Confirmed event-by-event against the OVMF event log and GCE event logs, sha1/256/384/512.
#
#   PCR3, PCR6  EV_SEPARATOR only (nothing else is measured there).
#   PCR4        EV_EFI_ACTION "Calling EFI Application from Boot Option", EV_SEPARATOR,
#               EV_EFI_BOOT_SERVICES_APPLICATION = Authenticode hash of the signed BOOT*.EFI.
#               (The embedded NIC drivers and the payload are loaded through stage0's own
#               Security2 override, which bypasses the firmware's image measurement: the
#               drivers are covered by stage0's own hash, the payload by PCR14.)
#   PCR5        EV_SEPARATOR, EV_EFI_GPT_EVENT = UEFI_GPT_DATA of boot.disk.
#   PCR7        SecureBoot, PK, KEK, db, dbx (EV_EFI_VARIABLE_DRIVER_CONFIG, the enrolled ESLs),
#               EV_SEPARATOR, EV_EFI_VARIABLE_AUTHORITY = the db entry that verified stage0.
#               The ESLs are rebuilt with mkvarstore.py's own code; on GCP they are
#               byte-identical because the owner GUID is GCP's (see gen-keys.sh).
#   PCR14       stage0's direct TPM2_PCR_Extend of its payload: H_bank(sha256(payload)), not
#               logged. An input (the payload is the deployment's choice).
#   PCR8-13, 15-23  not extended.
#
# Not modelled: PCR0-2 (provider firmware code, firmware boot entries, option ROMs). They are the
# platform's, inside the trust boundary its vTPM already implies, and change with its firmware
# updates: a per-platform replay file (golden readings) supplies them.
#
# Also writes pcrs.json (vaportpm layout): replaying this file alone, i.e. every PCR it models
# except the payload-dependent PCR14 -- the reference a verifier compares a quote against.
#
# usage: predict-pcrs.py <build-dir> [--banks sha256,sha384] --replay F [--out pcrs.json]
from __future__ import annotations

import argparse
import hashlib
import json
import os
import struct
import sys
import uuid
from typing import Any

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mkvarstore as mv  # noqa: E402

BOOT_EFI = {"x86_64": "BOOTX64.EFI", "aarch64": "BOOTAA64.EFI"}
SECTOR = 512
SEPARATOR = b"\0\0\0\0"
CALLING = "Calling EFI Application from Boot Option"


# --- event payloads (the data each event's digest is computed over) -----------------------------
def uefi_variable_data(vendor: uuid.UUID, name: str, data: bytes) -> bytes:
    """UEFI_VARIABLE_DATA: VariableName GUID, UnicodeNameLength, VariableDataLength, name, data."""
    return vendor.bytes_le + struct.pack("<QQ", len(name), len(data)) + name.encode("utf-16-le") + data


def authenticode(pe: bytes, H: Any) -> bytes:
    """Authenticode PE image hash (the digest firmware logs for a loaded image)."""
    pe_off = struct.unpack_from("<I", pe, 0x3C)[0]
    coff = pe_off + 4
    nsec, = struct.unpack_from("<H", pe, coff + 2)
    opt_size, = struct.unpack_from("<H", pe, coff + 16)
    opt = coff + 20
    magic, = struct.unpack_from("<H", pe, opt)
    checksum = opt + 64
    cert_dir = opt + (96 if magic == 0x10B else 112) + 4 * 8   # DataDirectory[4] (security)
    size_hdrs, = struct.unpack_from("<I", pe, opt + 60)
    cert_off, cert_len = struct.unpack_from("<II", pe, cert_dir)
    h = H()
    h.update(pe[:checksum])
    h.update(pe[checksum + 4:cert_dir])
    h.update(pe[cert_dir + 8:size_hdrs])
    secs = []
    for i in range(nsec):
        s = opt + opt_size + 40 * i
        raw_size, raw_ptr = struct.unpack_from("<II", pe, s + 16)
        if raw_size:
            secs.append((raw_ptr, raw_size))
    done = size_hdrs
    for ptr, size in sorted(secs):
        h.update(pe[ptr:ptr + size])
        done = max(done, ptr + size)
    end = len(pe) - (cert_len if cert_off else 0)
    if end > done:
        h.update(pe[done:end])
    return h.digest()


def gpt_data(disk_path: str) -> bytes:
    """UEFI_GPT_DATA: the primary GPT header, entry count, then the non-empty entries."""
    with open(disk_path, "rb") as f:
        f.seek(SECTOR)
        hdr = f.read(SECTOR)
        if hdr[:8] != b"EFI PART":
            raise SystemExit(f"{disk_path}: no GPT header at LBA 1")
        hsize, = struct.unpack_from("<I", hdr, 12)
        ent_lba, nent, esize = struct.unpack_from("<QII", hdr, 72)
        f.seek(ent_lba * SECTOR)
        raw = f.read(nent * esize)
    ents = [raw[i * esize:(i + 1) * esize] for i in range(nent)]
    used = [e for e in ents if e[:16] != b"\0" * 16]
    return hdr[:hsize] + struct.pack("<Q", len(used)) + b"".join(used)


# --- the replay file ------------------------------------------------------------------------------
def read(d: str, name: str) -> bytes:
    with open(os.path.join(d, name), "rb") as f:
        return f.read()


def owner(d: str, role: str) -> uuid.UUID:
    return uuid.UUID(read(d, f"{role}.guid").decode().strip())


def detect_arch(d: str) -> str:
    found = [a for a, f in BOOT_EFI.items() if os.path.exists(os.path.join(d, f))]
    if len(found) != 1:
        raise SystemExit(f"{d}: expected exactly one of {sorted(BOOT_EFI.values())}")
    return found[0]


def replay_file(d: str, banks: list[str]) -> dict[str, Any]:
    arch = detect_arch(d)
    efi_name = BOOT_EFI[arch]
    files = {n: read(d, n) for n in (efi_name, "boot.disk", "PK.cer", "KEK.cer", "db.cer", "dbx.esl")}
    gpt = gpt_data(os.path.join(d, "boot.disk"))
    own = {r: owner(d, r) for r in ("PK", "KEK", "db")}

    def var(vendor: uuid.UUID, name: str, data_expr: dict[str, Any]) -> dict[str, Any]:
        return {"uefi_variable": {"vendor": str(vendor), "name": name, "data": data_expr}}

    def esl(role: str) -> dict[str, Any]:
        return {"efi_signature_list": {"type": "x509", "owner": str(own[role]),
                                       "data": {"artifact": f"{role}.cer"}}}

    sep_expr = {"hex": SEPARATOR.hex()}
    # (pcr, type, by, about, derivation, digest mode, bytes for the local computation)
    G, S = mv.EFI_GLOBAL_VARIABLE, mv.IMAGE_SECURITY_DATABASE
    ev: list[tuple[int, str, str, str, dict[str, Any], str, bytes]] = [
        (3, "EV_SEPARATOR", "firmware", "", sep_expr, "hash", SEPARATOR),
        (4, "EV_EFI_ACTION", "firmware", "boot option dispatch", {"utf8": CALLING}, "hash", CALLING.encode()),
        (4, "EV_SEPARATOR", "firmware", "", sep_expr, "hash", SEPARATOR),
        (4, "EV_EFI_BOOT_SERVICES_APPLICATION", "firmware", f"stage0 ({efi_name}, Authenticode)",
         {"artifact": efi_name}, "authenticode", files[efi_name]),
        (5, "EV_SEPARATOR", "firmware", "", sep_expr, "hash", SEPARATOR),
        (5, "EV_EFI_GPT_EVENT", "firmware", "UEFI_GPT_DATA of boot.disk",
         {"gpt": {"artifact": "boot.disk"}}, "hash", gpt),
        (6, "EV_SEPARATOR", "firmware", "", sep_expr, "hash", SEPARATOR),
        (7, "EV_EFI_VARIABLE_DRIVER_CONFIG", "firmware", "SecureBoot = 1",
         var(G, "SecureBoot", {"hex": "01"}), "hash", uefi_variable_data(G, "SecureBoot", b"\x01")),
    ]
    for role, vendor in (("PK", G), ("KEK", G), ("db", S)):
        ev.append((7, "EV_EFI_VARIABLE_DRIVER_CONFIG", "firmware", f"{role}: one x509 ESL ({role}.cer)",
                   var(vendor, role, esl(role)), "hash",
                   uefi_variable_data(vendor, role, mv.sig_list_x509(files[f"{role}.cer"], own[role]))))
    ev += [
        (7, "EV_EFI_VARIABLE_DRIVER_CONFIG", "firmware", "dbx (dbx.esl)",
         var(S, "dbx", {"artifact": "dbx.esl"}), "hash", uefi_variable_data(S, "dbx", files["dbx.esl"])),
        (7, "EV_SEPARATOR", "firmware", "", sep_expr, "hash", SEPARATOR),
        (7, "EV_EFI_VARIABLE_AUTHORITY", "firmware", "the db entry that verified stage0",
         var(S, "db", {"concat": [{"guid": str(own["db"])}, {"artifact": "db.cer"}]}), "hash",
         uefi_variable_data(S, "db", own["db"].bytes_le + files["db.cer"])),
    ]
    events: list[dict[str, Any]] = []
    for pcr, typ, by, about, expr, mode, data in ev:
        e: dict[str, Any] = {"pcr": pcr, "type": typ, "by": by}
        if about:
            e["about"] = about
        e["derive"] = expr
        if mode != "hash":
            e["digest"] = mode
        e["digests"] = {b: (authenticode(data, getattr(hashlib, b)) if mode == "authenticode"
                            else getattr(hashlib, b)(data).digest()).hex() for b in banks}
        events.append(e)
    events.append({"pcr": 14, "type": "unlogged", "by": "stage0",
                   "about": "the payload stage0 verified and runs: H_bank(sha256(payload))",
                   "derive": {"input": "payload"}})
    return {
        "schema": "pcr-replay/v1",
        "name": f"stage0 {arch}",
        "about": "UEFI firmware and stage0, from TPM reset to the payload handoff (before "
                 "ExitBootServices). PCR0-2 are the platform's (a platform replay file).",
        "artifacts": {n: {"sha256": hashlib.sha256(b).hexdigest()} for n, b in files.items()},
        "entry": efi_name,
        "inputs": {"payload": {"about": "sha256 of the payload stage0 runs (the next stage)",
                               "next_entry": True}},
        "reset": list(range(3, 24)),
        "unextended": [0, 1, 2],
        "events": events,
    }


def reference_pcrs(rf: dict[str, Any], banks: list[str]) -> dict[str, Any]:
    """Replay the file's embedded digests from reset: every PCR it models except PCR14."""
    out: dict[str, dict[str, str]] = {}
    for b in banks:
        H = getattr(hashlib, b)
        n = H().digest_size
        p = {k: (b"\xff" if 17 <= k <= 22 else b"\0") * n for k in rf["reset"] if k != 14}
        for e in rf["events"]:
            if e["pcr"] in p:
                p[e["pcr"]] = H(p[e["pcr"]] + bytes.fromhex(e["digests"][b])).digest()
        out[b] = {str(k): v.hex() for k, v in sorted(p.items())}
    return {"pcrs": out}


def write_json(path: str, doc: dict[str, Any]) -> None:
    with open(path, "w") as f:
        json.dump(doc, f, indent=2)
        f.write("\n")


def main() -> None:
    ap = argparse.ArgumentParser(description="Write stage0's PCR replay file (and reference PCRs)")
    ap.add_argument("dir", help="stage0 build/<arch> or extracted release directory")
    ap.add_argument("--banks", default="sha256,sha384", help="comma-separated (default sha256,sha384)")
    ap.add_argument("--replay", required=True, help="write the pcr-replay/v1 file here")
    ap.add_argument("--out", help="also write the reference pcrs.json here")
    a = ap.parse_args()
    banks = a.banks.split(",")
    rf = replay_file(a.dir, banks)
    write_json(a.replay, rf)
    if a.out:
        write_json(a.out, reference_pcrs(rf, banks))


if __name__ == "__main__":
    main()
