#!/usr/bin/env python3
# Generate UEFI Secure Boot variable stores from x509 certs, in both the edk2
# (OVMF/AAVMF pflash) and AWS "AMZNUEFI" (EC2 --uefi-data) container formats.
#
# Pure Python standard library only -- this replaces `virt-fw-vars` (the
# virt-firmware package) in stage0's build so the entire enrolled varstore is
# produced by auditable code we own, byte-reproducibly. Every field below is
# derived from the on-disk edk2 structures (EFI_FIRMWARE_VOLUME_HEADER,
# VARIABLE_STORE_HEADER, AUTHENTICATED_VARIABLE_HEADER, EFI_SIGNATURE_LIST) and
# the AMZNUEFI v0 format (awslabs/python-uefivars); see REPRODUCIBLE-BUILDS.md.
#
# Determinism: unlike virt-fw-vars (which stamps wall-clock time into the
# PK/KEK/db authenticated variables, making its output differ every build), the
# authenticated-variable timestamp here is fixed from SOURCE_DATE_EPOCH.

import argparse
import base64
import os
import struct
import sys
import uuid

# --- Well-known GUIDs (constants from the UEFI spec / edk2) ------------------
EFI_GLOBAL_VARIABLE     = uuid.UUID("8be4df61-93ca-11d2-aa0d-00e098032b8c")
IMAGE_SECURITY_DATABASE = uuid.UUID("d719b2cb-3d3a-4596-a3bc-dad00e67656f")
CUSTOM_MODE_GUID        = uuid.UUID("c076ec0c-7028-4399-a072-71ee5c448b9f")
SECURE_BOOT_ENABLE_GUID = uuid.UUID("f0a30bc7-af08-4556-99c4-001009c93a44")
EFI_CERT_X509_GUID      = uuid.UUID("a5c059a1-94e4-4aa7-87b5-ab155c2bf072")
EFI_CERT_SHA256_GUID    = uuid.UUID("c1c41626-504c-4092-aca9-41f936934328")
NV_DATA_FV_GUID         = uuid.UUID("fff12b8d-7696-4c8b-a985-2747075b4f50")
AUTH_VAR_STORE_GUID     = uuid.UUID("aaf32c78-947b-439a-a180-2e144ec37792")

# virt-fw-vars adds a placeholder dbx: sha256("") owned by a fixed GUID, stamped
# 2010-01-01. Reproduced verbatim so our output matches the established shape.
DBX_DUMMY_OWNER = uuid.UUID("a0baa8a3-041d-48a8-bc87-c36d121b5e3d")
SHA256_EMPTY    = bytes.fromhex(
    "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855")

# UEFI variable attributes
NV, BS, RT, TIME_AUTH = 0x1, 0x2, 0x4, 0x20
ATTR_PLAIN = NV | BS                 # 0x03: NV + boot-services
ATTR_AUTH  = NV | BS | RT | TIME_AUTH  # 0x27: + runtime + time-based auth

# edk2 variable-store state/format bytes
VAR_ADDED    = 0x3f    # AUTHENTICATED_VARIABLE_HEADER.State for a live variable
VS_FORMATTED = 0x5a    # VARIABLE_STORE_HEADER.Format
VS_HEALTHY   = 0xfe    # VARIABLE_STORE_HEADER.State
VAR_START_ID = 0x55aa


# --- EFI_TIME ---------------------------------------------------------------
def efi_time(epoch):
    """16-byte EFI_TIME from a UNIX epoch (UTC), nanosecond/timezone/daylight 0."""
    import time
    t = time.gmtime(epoch)
    return struct.pack("<HBBBBBBIhBB",
                       t.tm_year, t.tm_mon, t.tm_mday,
                       t.tm_hour, t.tm_min, t.tm_sec,
                       0, 0, 0, 0, 0)


EFI_TIME_ZERO = b"\x00" * 16
# fixed EFI_TIME for the placeholder dbx (2010-01-01T00:00:00), matching the tool
EFI_TIME_DBX = struct.pack("<HBBBBBBIhBB", 2010, 1, 1, 0, 0, 0, 0, 0, 0, 0, 0)


# --- EFI_SIGNATURE_LIST -----------------------------------------------------
def sig_list_x509(cert_der, owner):
    """One EFI_SIGNATURE_LIST holding a single x509 cert (SignatureHeaderSize 0)."""
    sig = owner.bytes_le + cert_der           # EFI_SIGNATURE_DATA
    sig_size = len(sig)
    list_size = 16 + 4 + 4 + 4 + sig_size     # type + 3 sizes + one signature
    return (EFI_CERT_X509_GUID.bytes_le
            + struct.pack("<III", list_size, 0, sig_size) + sig)


def sig_list_sha256(digest, owner):
    """One EFI_SIGNATURE_LIST holding a single sha256 hash (fixed 32+16 sig)."""
    sig = owner.bytes_le + digest
    sig_size = len(sig)                        # 48
    list_size = 16 + 4 + 4 + 4 + sig_size
    return (EFI_CERT_SHA256_GUID.bytes_le
            + struct.pack("<III", list_size, 0, sig_size) + sig)


# --- one enrolled variable (metadata + raw data) ----------------------------
class Var:
    __slots__ = ("name", "guid", "attr", "timestamp", "data")

    def __init__(self, name, guid, attr, data, timestamp=EFI_TIME_ZERO):
        self.name = name
        self.guid = guid
        self.attr = attr
        self.timestamp = timestamp
        self.data = data


def pem_to_der(path):
    """Load an x509 cert (PEM or DER) and return DER bytes (stdlib only)."""
    raw = open(path, "rb").read()
    if raw[:1] == b"\x30":            # already DER (SEQUENCE)
        return raw
    body = []
    keep = False
    for line in raw.decode("ascii").splitlines():
        if line.startswith("-----BEGIN"):
            keep = True
            continue
        if line.startswith("-----END"):
            break
        if keep:
            body.append(line.strip())
    return base64.b64decode("".join(body))


def secureboot_vars(pk_der, kek_der, db_der, pk_owner, kek_owner, db_owner,
                    auth_time):
    """The canonical 7-variable Secure Boot enrollment, in virt-fw-vars order."""
    return [
        Var("CustomMode",       CUSTOM_MODE_GUID,        ATTR_PLAIN, b"\x00"),
        Var("DeployedMode",     EFI_GLOBAL_VARIABLE,     ATTR_PLAIN, b"\x01"),
        Var("KEK",  EFI_GLOBAL_VARIABLE, ATTR_AUTH,
            sig_list_x509(kek_der, kek_owner), auth_time),
        Var("PK",   EFI_GLOBAL_VARIABLE, ATTR_AUTH,
            sig_list_x509(pk_der, pk_owner), auth_time),
        Var("SecureBootEnable", SECURE_BOOT_ENABLE_GUID, ATTR_PLAIN, b"\x01"),
        Var("db",   IMAGE_SECURITY_DATABASE, ATTR_AUTH,
            sig_list_x509(db_der, db_owner), auth_time),
        Var("dbx",  IMAGE_SECURITY_DATABASE, ATTR_AUTH,
            sig_list_sha256(SHA256_EMPTY, DBX_DUMMY_OWNER), EFI_TIME_DBX),
    ]


# --- edk2 (OVMF/AAVMF pflash varstore) serialization ------------------------
def _fv_checksum(hdr):
    """16-bit sum of all UINT16 words in the FV header must be 0."""
    s = sum(struct.unpack_from("<H", hdr, i)[0] for i in range(0, len(hdr), 2))
    return (-s) & 0xffff


def serialize_edk2(varlist, total_size, fv_length, block_map, fv_attr,
                   varstore_size, tail):
    """
    Build a full pflash varstore image:
      [EFI_FIRMWARE_VOLUME_HEADER][VARIABLE_STORE_HEADER][vars..][0xFF..][tail]
    total_size    = full pflash device length (file size)
    fv_length     = EFI_FIRMWARE_VOLUME_HEADER.FvLength (may be < total_size:
                    on aarch64 the FV is only the first blocks, rest is padding)
    block_map     = list of (NumBlocks, BlockLength) for the FV header block map
    fv_attr       = EFI_FIRMWARE_VOLUME_HEADER.Attributes (arch-specific)
    varstore_size = VARIABLE_STORE_HEADER.Size (variable region after FV header)
    tail          = bytes for everything after the variable region (FTW region +
                    any device padding); spans var_region_end..total_size
    """
    hdr_len = 0x48
    # --- EFI_FIRMWARE_VOLUME_HEADER ---
    fv = bytearray()
    fv += b"\x00" * 16                       # ZeroVector
    fv += NV_DATA_FV_GUID.bytes_le           # FileSystemGuid
    fv += struct.pack("<Q", fv_length)       # FvLength
    fv += b"_FVH"                            # Signature
    fv += struct.pack("<I", fv_attr)         # Attributes
    fv += struct.pack("<H", hdr_len)         # HeaderLength
    fv += struct.pack("<H", 0)               # Checksum (filled below)
    fv += struct.pack("<H", 0)               # ExtHeaderOffset
    fv += b"\x00"                           # Reserved
    fv += b"\x02"                           # Revision
    for nblocks, blocklen in block_map:      # BlockMap[]
        fv += struct.pack("<II", nblocks, blocklen)
    fv += struct.pack("<II", 0, 0)           # BlockMap[] terminator
    assert len(fv) == hdr_len, len(fv)
    struct.pack_into("<H", fv, 0x32, _fv_checksum(fv))

    # --- VARIABLE_STORE_HEADER ---
    vs = bytearray()
    vs += AUTH_VAR_STORE_GUID.bytes_le
    vs += struct.pack("<IBBHI", varstore_size, VS_FORMATTED, VS_HEALTHY, 0, 0)

    # --- AUTHENTICATED_VARIABLE_HEADER records ---
    body = bytearray()
    for v in varlist:
        name = v.name.encode("utf-16-le") + b"\x00\x00"
        body += struct.pack("<HBBIQ16sIII16s",
                            VAR_START_ID, VAR_ADDED, 0, v.attr, 0,
                            v.timestamp, 0, len(name), len(v.data),
                            v.guid.bytes_le)
        body += name + v.data
        while len(body) % 4:                 # 4-byte align, pad 0xFF
            body += b"\xff"

    varstore = fv + vs + body
    # free space (0xFF) fills the variable region out to varstore_size
    var_region_end = hdr_len + varstore_size
    varstore += b"\xff" * (var_region_end - len(varstore))
    varstore += tail
    assert len(varstore) == total_size, (len(varstore), total_size)
    return bytes(varstore)


# --- AWS AMZNUEFI v0 serialization ------------------------------------------
AMZNUEFI = 0x494645554e5a4d41

# CRC32C (Castagnoli); AMZNUEFI checksums with this, not the zlib CRC32.
_CRC32C_TABLE = []
def _crc32c(data, crc=0xffffffff):
    if not _CRC32C_TABLE:
        for n in range(256):
            c = n
            for _ in range(8):
                c = (c >> 1) ^ (0x82f63b78 & -(c & 1))
            _CRC32C_TABLE.append(c & 0xffffffff)
    for b in data:
        crc = _CRC32C_TABLE[(crc ^ b) & 0xff] ^ (crc >> 8)
    return crc ^ 0xffffffff


def serialize_aws(varlist, dict_path):
    import zlib
    zdict = open(dict_path, "rb").read()
    raw = bytearray()
    raw += struct.pack("<Q", len(varlist))
    for v in varlist:
        name = v.name.encode("utf-8")
        raw += struct.pack("<Q", len(name)) + name
        raw += struct.pack("<Q", len(v.data)) + v.data
        raw += v.guid.bytes_le
        raw += struct.pack("<I", v.attr)
        if v.attr & TIME_AUTH:
            raw += v.timestamp                 # 16-byte EFI_TIME
            raw += struct.pack("<Q", 0)        # empty digest
    enc = zlib.compressobj(9, zdict=zdict)
    zdata = enc.compress(bytes(raw)) + enc.flush()
    out = struct.pack("<Q", AMZNUEFI)
    out += struct.pack("<I", _crc32c(b"\x00\x00\x00\x00" + zdata))
    out += struct.pack("<I", 0)                # version 0
    out += zdata
    return base64.b64encode(out)


# --- per-arch flash geometry ------------------------------------------------
# The trailing region after the variable store holds edk2's fault-tolerant-write
# (FTW) area -- a 32-byte working-block header (its own CRC over erased space,
# key-independent) plus erased 0xFF -- then any device padding. Captured verbatim
# from the reference varstores (OVMF_VARS_4M.fd / AAVMF_VARS). See the FTW notes
# in REPRODUCIBLE-BUILDS.md.
def _tail_x86():
    # 0x40000..0x84000: 4 KB erased, working block @0x41000, erased to end.
    tail = bytearray(b"\xff" * 0x44000)
    tail[0x1000:0x1000 + 32] = bytes.fromhex(
        "2b29589e687c7d49a0ce6500fd9f1b952caf2c64feffffffe00f000000000000")
    return bytes(tail)


def _tail_aarch64():
    # 0x40000..0xc0000: working block @0x40000 + erased spare (within FvLength);
    # 0xc0000..0x4000000: 0x00 device padding out to the 64 MB pflash size.
    ftw = bytearray(b"\xff" * 0x80000)
    ftw[0:32] = bytes.fromhex(
        "2b29589e687c7d49a0ce6500fd9f1b955be7c686feffffffe0ff030000000000")
    return bytes(ftw) + b"\x00" * (0x4000000 - 0xc0000)


PROFILES = {
    "x86_64": dict(total_size=0x84000, fv_length=0x84000,
                   block_map=[(132, 0x1000)], fv_attr=0x0004feff,
                   varstore_size=0x3ffb8, tail=_tail_x86),
    "aarch64": dict(total_size=0x4000000, fv_length=0xc0000,
                    block_map=[(256, 0x40000)], fv_attr=0x00000e36,
                    varstore_size=0x3ffb8, tail=_tail_aarch64),
}


def main():
    ap = argparse.ArgumentParser(description="Generate edk2 + AWS SB varstores")
    ap.add_argument("--arch", required=True, choices=sorted(PROFILES))
    ap.add_argument("--pk", required=True)
    ap.add_argument("--kek", required=True)
    ap.add_argument("--db", required=True)
    ap.add_argument("--pk-guid", required=True)
    ap.add_argument("--kek-guid", required=True)
    ap.add_argument("--db-guid", required=True)
    ap.add_argument("--dict", required=True, help="AMZNUEFI v0 preset dictionary")
    ap.add_argument("--out-ovmf", required=True)
    ap.add_argument("--out-aws", required=True)
    args = ap.parse_args()

    epoch = int(os.environ.get("SOURCE_DATE_EPOCH", "0"))
    auth_time = efi_time(epoch)
    varlist = secureboot_vars(
        pem_to_der(args.pk), pem_to_der(args.kek), pem_to_der(args.db),
        uuid.UUID(open(args.pk_guid).read().strip()),
        uuid.UUID(open(args.kek_guid).read().strip()),
        uuid.UUID(open(args.db_guid).read().strip()),
        auth_time)

    p = PROFILES[args.arch]
    img = serialize_edk2(varlist, p["total_size"], p["fv_length"],
                         p["block_map"], p["fv_attr"], p["varstore_size"],
                         p["tail"]())
    open(args.out_ovmf, "wb").write(img)
    open(args.out_aws, "wb").write(serialize_aws(varlist, args.dict))


if __name__ == "__main__":
    main()
