#!/usr/bin/env python3
# Reproduce stage0's PCR values from its release artifacts -- the root of the verification path.
#
# Given a stage0 build/release directory, compute the PCRs the firmware will hold when stage0
# hands off to its payload (before ExitBootServices), per bank, by replaying the exact event
# sequence UEFI firmware logs (confirmed event-by-event against the OVMF event log and the GCE
# logs in go-tpm-tools' test data; values match QEMU and GCP across sha1/sha256/sha384/sha512):
#
#   PCR3, PCR6  EV_SEPARATOR only (nothing else is measured there).
#   PCR4        EV_EFI_ACTION "Calling EFI Application from Boot Option", EV_SEPARATOR,
#               EV_EFI_BOOT_SERVICES_APPLICATION = Authenticode hash of the signed BOOT*.EFI.
#               (The embedded NIC drivers and the payload are loaded through stage0's own
#               Security2 override, which bypasses the firmware's image measurement: the
#               drivers are covered by stage0's own hash, the payload by PCR14.)
#   PCR5        EV_SEPARATOR, EV_EFI_GPT_EVENT = UEFI_GPT_DATA of boot.disk
#               (header || NumberOfPartitions || the non-empty partition entries).
#   PCR7        SecureBoot=1, PK, KEK, db, dbx (EV_EFI_VARIABLE_DRIVER_CONFIG, the enrolled ESLs),
#               EV_SEPARATOR, then EV_EFI_VARIABLE_AUTHORITY = the db entry that verified stage0.
#               The ESLs are rebuilt with mkvarstore.py's own code; on GCP they are
#               byte-identical because the owner GUID is GCP's (see gen-keys.sh).
#   PCR14       (with --payload-sha256) stage0's direct TPM2_PCR_Extend of the payload digest:
#               not in the event log; event digest = H_bank(sha256(payload)).
#
# Not reproduced, by design: PCR0 (firmware code), PCR1 (firmware-created boot entries), PCR2
# (option ROMs / platform drivers). They measure the provider's own firmware and configuration,
# which sits inside the trust boundary the provider's vTPM already implies, and they change with
# provider firmware updates -- record them as per-instance-type golden readings, never bind keys
# to them.
#
# Output (vaportpm JSON layout): {"pcrs": {"sha256": {"4": "<hex>", ...}, "sha384": {...}}}
#
# usage: predict-pcrs.py <build-dir> [--payload-sha256 HEX] [--banks sha256,sha384] [--out F]
#        predict-pcrs.py <build-dir> --check <serial.log>   (compare against the test payload's
#                                                             "payload: PCR <alg> <nn> <hex>" dump)
import argparse
import hashlib
import json
import os
import re
import struct
import sys
import uuid

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import mkvarstore as mv  # noqa: E402

BOOT_EFI = {"x86_64": "BOOTX64.EFI", "aarch64": "BOOTAA64.EFI"}
SECTOR = 512


# --- event payloads (the data each event's digest is computed over) -----------------------------
def uefi_variable_data(vendor, name, data):
    """UEFI_VARIABLE_DATA: VariableName GUID, UnicodeNameLength, VariableDataLength, name, data."""
    n = name.encode("utf-16-le")
    return vendor.bytes_le + struct.pack("<QQ", len(name), len(data)) + n + data


def authenticode(pe, H):
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


def gpt_data(disk_path):
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


# --- prediction ------------------------------------------------------------------------------------
def read(d, name):
    with open(os.path.join(d, name), "rb") as f:
        return f.read()


def owner(d, role):
    return uuid.UUID(read(d, f"{role}.guid").decode().strip())


def detect_arch(d):
    found = [a for a, f in BOOT_EFI.items() if os.path.exists(os.path.join(d, f))]
    if len(found) != 1:
        raise SystemExit(f"{d}: expected exactly one of {sorted(BOOT_EFI.values())}")
    return found[0]


def predict(d, banks, payload_sha256=None):
    arch = detect_arch(d)
    efi = read(d, BOOT_EFI[arch])
    gpt = gpt_data(os.path.join(d, "boot.disk"))
    pk, kek, db = read(d, "PK.cer"), read(d, "KEK.cer"), read(d, "db.cer")
    db_owner = owner(d, "db")
    pcr7_events = [
        uefi_variable_data(mv.EFI_GLOBAL_VARIABLE, "SecureBoot", b"\x01"),
        uefi_variable_data(mv.EFI_GLOBAL_VARIABLE, "PK", mv.sig_list_x509(pk, owner(d, "PK"))),
        uefi_variable_data(mv.EFI_GLOBAL_VARIABLE, "KEK", mv.sig_list_x509(kek, owner(d, "KEK"))),
        uefi_variable_data(mv.IMAGE_SECURITY_DATABASE, "db", mv.sig_list_x509(db, db_owner)),
        uefi_variable_data(mv.IMAGE_SECURITY_DATABASE, "dbx", read(d, "dbx.esl")),
        None,  # separator
        # EV_EFI_VARIABLE_AUTHORITY: the EFI_SIGNATURE_DATA (owner || cert) that verified stage0
        uefi_variable_data(mv.IMAGE_SECURITY_DATABASE, "db", db_owner.bytes_le + db),
    ]

    out = {}
    for bank in banks:
        H = getattr(hashlib, bank)
        sep = H(b"\0\0\0\0").digest()

        def chain(digests):
            v = b"\0" * H().digest_size
            for e in digests:
                v = H(v + e).digest()
            return v.hex()

        p = {
            3: chain([sep]),
            4: chain([H(b"Calling EFI Application from Boot Option").digest(), sep,
                      authenticode(efi, H)]),
            5: chain([sep, H(gpt).digest()]),
            6: chain([sep]),
            7: chain([sep if e is None else H(e).digest() for e in pcr7_events]),
        }
        if payload_sha256:
            p[14] = chain([H(bytes.fromhex(payload_sha256)).digest()])
        out[bank] = {str(k): v for k, v in sorted(p.items())}
    return {"pcrs": out}


def check(pred, log_path):
    with open(log_path, "rb") as f:
        txt = f.read().decode("latin1")
    seen = {(a, int(i)): v for a, i, v in re.findall(r"payload: PCR (\w+) (\d\d) ([0-9a-f]+)", txt)}
    bad = 0
    for bank, pcrs in pred["pcrs"].items():
        for i, want in pcrs.items():
            got = seen.get((bank, int(i)))
            status = "ok" if got == want else ("MISSING" if got is None else "MISMATCH")
            bad += status != "ok"
            print(f"{bank:7} PCR{int(i):<2} {status:8} predicted {want[:16]}"
                  + ("" if status == "ok" or got is None else f"  read {got[:16]}"))
    print("ALL PREDICTED PCRS MATCH" if not bad else f"{bad} PREDICTED PCR(S) DO NOT MATCH")
    return bad == 0


def main():
    ap = argparse.ArgumentParser(description="Reproduce stage0's PCRs from its release artifacts")
    ap.add_argument("dir", help="stage0 build/<arch> or extracted release directory")
    ap.add_argument("--payload-sha256", help="also predict PCR14 for this payload digest")
    ap.add_argument("--banks", default="sha256,sha384", help="comma-separated (default sha256,sha384)")
    ap.add_argument("--out", help="write JSON here (default stdout)")
    ap.add_argument("--check", metavar="LOG", help="compare against a test-payload serial log")
    a = ap.parse_args()
    pred = predict(a.dir, a.banks.split(","), a.payload_sha256)
    if a.check:
        sys.exit(0 if check(pred, a.check) else 1)
    js = json.dumps(pred, indent=2) + "\n"
    if a.out:
        with open(a.out, "w") as f:
            f.write(js)
    else:
        sys.stdout.write(js)


if __name__ == "__main__":
    main()
