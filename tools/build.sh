#!/bin/bash
# Build a bootable disk image that boots stage0.efi directly (no kernel/UKI).
#
# Builds a GPT + FAT32 ESP whose sole payload is the db-signed stage0 UEFI
# application (no kernel/UKI). Deterministic GUIDs/timestamps for reproducibility.
#
# Requires privilege for losetup/mount (run inside the privileged build docker,
# or with sudo on the host). Uses stage0's own snakeoil Secure Boot keys from
# build/keys (db-signs stage0.efi and enrolls PK/KEK/db).
set -euox pipefail

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
REPO_ROOT="$(cd "${SCRIPT_DIR}/.." && pwd)"

ARCH="${ARCH:-x86_64}"
KEYDIR="${REPO_ROOT}/build/keys"
OUTPUT_DIR="${OUTPUT_DIR:-${REPO_ROOT}/build/${ARCH}}"
STAGE0_EFI="${STAGE0_EFI:-${OUTPUT_DIR}/stage0.efi}"

case "${ARCH}" in
  x86_64)  BOOT_EFI="BOOTX64.EFI" ;;
  aarch64) BOOT_EFI="BOOTAA64.EFI" ;;
  *) echo "Unsupported ARCH: ${ARCH}"; exit 1 ;;
esac

if [ ! -f "${STAGE0_EFI}" ]; then
    echo "Error: stage0 EFI binary not found at ${STAGE0_EFI}"
    echo "Build it first: make build/${ARCH}/stage0.efi"
    exit 1
fi

mkdir -p "${OUTPUT_DIR}"

# --- Sign stage0.efi for Secure Boot (stage0's own db key) ---
SIGNED_EFI="${OUTPUT_DIR}/${BOOT_EFI}"
echo "=== Signing stage0.efi ==="
sbsign --key "${KEYDIR}/db.crt.key" --cert "${KEYDIR}/db.crt" --output "${SIGNED_EFI}" "${STAGE0_EFI}"

# --- Create the bootable GPT + FAT32 disk ---
echo "=== Creating bootable disk image ==="
EFI_SIZE_BYTES=$(stat -c%s "${SIGNED_EFI}")
EFI_SIZE_MB=$((EFI_SIZE_BYTES / 1024 / 1024 + 1))
PARTITION_SIZE_MB=$((EFI_SIZE_MB * 3 / 2))
if [ ${PARTITION_SIZE_MB} -lt 64 ]; then PARTITION_SIZE_MB=64; fi
DISK_SIZE_MB=$((PARTITION_SIZE_MB + 2))

DISK_IMAGE="${OUTPUT_DIR}/boot.disk"
dd if=/dev/zero of="${DISK_IMAGE}" bs=1M count=${DISK_SIZE_MB} status=none

# Fixed lockboot GUIDs / FAT volume-id: CONSTANT across releases, so the GPT (and hence
# the firmware's PCR 5 measurement) is byte-stable, and a lockboot disk is identifiable
# by GUID. "4c4f434b424f4f54" spells "LOCKBOOT"; the last group is a role index
# (disk = 0, ESP = partition 1).
DISK_GUID="4c4f434b-424f-4f54-0000-000000000000"
PART_GUID="4c4f434b-424f-4f54-0000-000000000001"
VOLUME_ID="4c4f434b"
# stage0.efi hash — still used for BUILD_ID below.
EFI_HASH=$(sha256sum "${SIGNED_EFI}" | cut -d' ' -f1)

sfdisk "${DISK_IMAGE}" <<EOF
label: gpt
label-id: ${DISK_GUID}
first-lba: 2048
unit: sectors

start=2048, size=$((((DISK_SIZE_MB - 1) * 1024 * 1024 / 512) - 2048)), type=C12A7328-F81F-11D2-BA4B-00A0C93EC93B, uuid=${PART_GUID}, name="EFI System Partition"
EOF

PART_INFO=$(sfdisk -d "${DISK_IMAGE}" | grep "start=" | head -1)
PART_START_SECTOR=$(echo "${PART_INFO}" | sed -n 's/.*start=\s*\([0-9]*\).*/\1/p')
PART_OFFSET=$((PART_START_SECTOR * 512))

LOOP_DEVICE=$(losetup -f --show -o "${PART_OFFSET}" "${DISK_IMAGE}")
mkfs.vfat -F 32 -n "EFISYS" -i "${VOLUME_ID}" "${LOOP_DEVICE}"

MOUNT_DIR="${OUTPUT_DIR}/tmp/esp-mount-$$"
mkdir -p "${MOUNT_DIR}"
mount -o noatime,nodiratime,tz=UTC "${LOOP_DEVICE}" "${MOUNT_DIR}"
mkdir -p "${MOUNT_DIR}/EFI/BOOT"
cp "${SIGNED_EFI}" "${MOUNT_DIR}/EFI/BOOT/${BOOT_EFI}"
find "${MOUNT_DIR}" -exec touch -h -d "1980-01-01 00:00:00 UTC" {} +
sync
umount "${MOUNT_DIR}"
rmdir "${MOUNT_DIR}"
losetup -d "${LOOP_DEVICE}"
rm -rf "${OUTPUT_DIR}/tmp"

if [ -x "${REPO_ROOT}/tools/normalize-fat-timestamps.py" ]; then
    "${REPO_ROOT}/tools/normalize-fat-timestamps.py" "${DISK_IMAGE}" "${PART_OFFSET}" || true
fi

echo "Disk image created: ${DISK_IMAGE}"
ls -lh "${DISK_IMAGE}"

# --- Generate Secure Boot variables (OVMF + AWS) from stage0's own keys ---
# tools/mkvarstore.py builds the whole enrolled varstore (edk2 pflash + AWS
# AMZNUEFI) from scratch in pure-stdlib Python -- no virt-fw-vars, no distro
# firmware template. Only stage0's PK/KEK/db are enrolled, and the output is
# byte-reproducible (auth-variable timestamp fixed from SOURCE_DATE_EPOCH).
EFI_VARS_OVMF="${OUTPUT_DIR}/efi-vars.ovmf"
EFI_VARS_AWS="${OUTPUT_DIR}/efi-vars.aws"
python3 "${REPO_ROOT}/tools/mkvarstore.py" --arch "${ARCH}" \
  --pk  "${KEYDIR}/PK.crt"  --pk-guid  "${KEYDIR}/PK.guid" \
  --kek "${KEYDIR}/KEK.crt" --kek-guid "${KEYDIR}/KEK.guid" \
  --db  "${KEYDIR}/db.crt"  --db-guid  "${KEYDIR}/db.guid" \
  --dict "${REPO_ROOT}/tools/firmware/amznuefi-v0.dict" \
  --out-ovmf "${EFI_VARS_OVMF}" --out-aws "${EFI_VARS_AWS}" \
  --out-dbx "${OUTPUT_DIR}/dbx.esl" \
  --out-dbx-auth "${OUTPUT_DIR}/dbx.auth.bin" --kek-key "${KEYDIR}/KEK.crt.key"
echo "EFI vars written: ${EFI_VARS_OVMF}"

# Emit os-release so the cloud publishers can name/tag the image. BUILD_ID is
# derived from the signed stage0 hash so each build is traceable.
OSREL_PATH="${OUTPUT_DIR}/os-release"
YEAR_MONTH=$(date +%y.%m)
{
  echo "ID=lockboot"
  echo "VERSION_ID=${YEAR_MONTH}"
  echo "NAME=\"Lock.Boot stage0\""
  echo "PRETTY_NAME=\"Lock.Boot stage0 ${YEAR_MONTH} ${ARCH}\""
  echo "BUILD_ID=stage0-${EFI_HASH:0:12}"
} > "${OSREL_PATH}"

# Copy the public Secure Boot enrollment material next to boot.disk + efi-vars so
# the GCP publisher (and manual enrollment) gets the certs in one release bundle.
# The private *.crt.key is intentionally NOT copied (ephemeral, stays in keys/).
for f in db.cer db.guid PK.cer PK.guid KEK.cer KEK.guid; do
    [ -f "${KEYDIR}/${f}" ] && cp "${KEYDIR}/${f}" "${OUTPUT_DIR}/"
done

if [ -n "${OWNER_UID:-}" ] && [ -n "${OWNER_GID:-}" ]; then
    chown -R "${OWNER_UID}:${OWNER_GID}" "${OUTPUT_DIR}"
fi
