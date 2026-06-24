#!/bin/bash
# Snapshot a stage0 boot disk straight to EBS (via coldsnap / EBS Direct API) and
# register a UEFI/TPM-v2 AMI. The AMI is made publicly launchable unless --private.
#
# All progress goes to stderr; the created AMI ID is printed to stdout, so it can be
# captured:  AMI=$(create.sh x86_64)  then  aws ec2 run-instances --image-id "$AMI"

set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1${2:+ ($2)}"; }
# Append a created-resource line to the manifest (if --manifest was given).
record() { [ -n "${MANIFEST:-}" ] || return 0; printf '%s\n' "$*" >> "${MANIFEST}"; }

DEFAULT_REGION="ap-southeast-1"   # AWS Singapore (always-on; KL ap-southeast-5 is opt-in)

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] <arch> [version]

Build (or download) a stage0 boot disk and register it as an AMI.

Arguments:
  arch       x86_64 | aarch64
  version    a stage0-v* release tag, or 'local' (default) for a local build

Options:
  --region <r>  AWS region (default: ${DEFAULT_REGION})
  --public      make the AMI publicly launchable by any AWS account (default)
  --private     keep the AMI private to this account
  --no-verify   (release mode) skip gh attestation; fetch the public release asset
                via curl so no gh install is needed
  --no-secure-boot  DEBUG: register the AMI WITHOUT enrolling Secure Boot keys (no
                --uefi-data), so the firmware is in setup mode and loads stage0 even
                if signing/db don't match. Use to isolate "zero serial output" boots:
                if stage0 logs with this but not without, the efi-vars.aws db is wrong.
                Registers a separate '-nosb' AMI; never use for production.
  --manifest <f>  append created resources to <f> for a teardown script, one per
                  line: "aws <kind> <region> <id>" (snapshot, ami)
  -h, --help    show this help and exit

Examples:
  $(basename "$0") x86_64                          # local build -> public AMI in ${DEFAULT_REGION}
  $(basename "$0") --region us-east-1 x86_64 stage0-v0.1.0
  $(basename "$0") --private aarch64
EOF
}

REGION="${DEFAULT_REGION}"
PUBLIC=true
NO_VERIFY=false
SECURE_BOOT=true
MANIFEST=""
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --region)     REGION="${2:?--region needs a value}"; shift 2 ;;
        --region=*)   REGION="${1#*=}"; shift ;;
        --public)     PUBLIC=true; shift ;;
        --private)    PUBLIC=false; shift ;;
        --no-verify)  NO_VERIFY=true; shift ;;
        --no-secure-boot) SECURE_BOOT=false; shift ;;
        --manifest)   MANIFEST="${2:?--manifest needs a value}"; shift 2 ;;
        --manifest=*) MANIFEST="${1#*=}"; shift ;;
        -h|--help)    usage; exit 0 ;;
        --) shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
        -*) echo "Error: unknown option: $1" >&2; usage; exit 1 ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]}"
[ $# -ge 1 ] || { usage; exit 1; }

ARCH="$1"
VERSION="${2:-local}"

[ "${ARCH}" = "x86_64" ] || [ "${ARCH}" = "aarch64" ] || die "arch must be x86_64 or aarch64"
case "${ARCH}" in aarch64) EC2_ARCH="arm64" ;; *) EC2_ARCH="${ARCH}" ;; esac

# ---- preflight: tools + credentials, before any slow work ----
require_cmd aws "install the AWS CLI"
require_cmd coldsnap "cargo install --locked coldsnap"
# get-caller-identity is a global call: do NOT pin it to ${REGION}, or an opt-in
# region (e.g. ap-southeast-5) whose regional STS endpoint isn't enabled yet would
# make a valid credential look broken.
aws sts get-caller-identity >/dev/null 2>&1 \
    || die "AWS credentials not working (aws sts get-caller-identity failed); run 'aws configure' or set AWS_PROFILE"

# Opt-in regions (KL, Jakarta, etc.) must be enabled on the account before any
# regional API works. describe-regions is queried from us-east-1 (always on) so this
# check itself can't be tripped by the very region we're testing.
OPT_IN=$(aws ec2 describe-regions --region us-east-1 --all-regions \
    --region-names "${REGION}" --query 'Regions[0].OptInStatus' --output text 2>/dev/null || echo "")
case "${OPT_IN}" in
    opted-in|opt-in-not-required) ;;  # usable
    not-opted-in) die "region ${REGION} is not enabled on this account. Enable it (Account > AWS Regions, or: aws account enable-region --region-name ${REGION}), wait for it to finish, then re-run. Or pass --region ap-southeast-1 (Singapore)." ;;
    *) echo "WARN: could not determine opt-in status for ${REGION} (got '${OPT_IN:-}'); continuing" ;;
esac

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

# Single cleanup hook for every temp path we create.
CLEANUP=()
cleanup() { local p; for p in "${CLEANUP[@]:-}"; do [ -n "$p" ] && rm -rf "$p"; done; }
trap cleanup EXIT

# Save real stdout on fd 3 and route everything else to stderr, so the only thing
# on stdout is the final AMI ID (printed via >&3). Command substitutions are
# unaffected. Done after --help/arg parsing so usage still prints to stdout.
exec 3>&1 1>&2

# ---- resolve the boot disk + Secure Boot vars: local build or verified release ----
if [ "${VERSION}" != "local" ]; then
    require_cmd unzip
    echo "=== Downloading release ${VERSION} from GitHub ==="
    TEMP_DIR=$(mktemp -d); CLEANUP+=("${TEMP_DIR}")
    GH_REPO=$(git remote get-url origin 2>/dev/null | sed 's/.*github.com[:/]\(.*\)\.git/\1/' || echo "")
    [ -n "${GH_REPO}" ] || die "could not determine GitHub repository from 'git remote get-url origin'"
    ZIP="${TEMP_DIR}/stage0-${ARCH}.zip"
    if [ "${NO_VERIFY}" = "true" ]; then
        require_cmd curl
        URL="https://github.com/${GH_REPO}/releases/download/${VERSION}/stage0-${ARCH}.zip"
        echo "Fetching ${URL} via curl (--no-verify: no gh, attestation NOT checked)"
        curl -fSL -o "${ZIP}" "${URL}" || die "download failed (public release asset only): ${URL}"
        echo "WARNING: --no-verify set: release attestation was NOT verified"
    else
        require_cmd gh "install the GitHub CLI, or pass --no-verify to fetch via curl"
        echo "Repository: ${GH_REPO}; fetching stage0-${ARCH}.zip @ ${VERSION}"
        gh release download "${VERSION}" --repo "${GH_REPO}" --pattern "stage0-${ARCH}.zip" --dir "${TEMP_DIR}" \
            || die "failed to download stage0-${ARCH}.zip from release ${VERSION}"
        gh attestation verify "${ZIP}" --repo "${GH_REPO}" \
            || die "attestation verification failed for stage0-${ARCH}.zip"
    fi
    unzip -q "${ZIP}" -d "${TEMP_DIR}"
    WORK_DIR="${TEMP_DIR}"
    echo "Using release files from ${VERSION}"
else
    echo "=== Using local build files ==="
    WORK_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)/build/${ARCH}"
fi

IMAGE_FILE="${WORK_DIR}/boot.disk"
UEFI_DATA_FILE="${WORK_DIR}/efi-vars.aws"
OS_RELEASE_FILE="${WORK_DIR}/os-release"
for f in "${OS_RELEASE_FILE}" "${IMAGE_FILE}" "${UEFI_DATA_FILE}"; do
    [ -f "$f" ] || die "required file not found: $f (build it first: make build-${ARCH})"
done

# os-release provides ID, VERSION_ID, BUILD_ID, NAME, PRETTY_NAME (our own artifact).
# shellcheck disable=SC1090
source "${OS_RELEASE_FILE}"

AMI_NAME="${ID}-${ARCH}-${VERSION_ID}-${BUILD_ID}"
# A no-Secure-Boot debug AMI is a distinct image (don't collide with the real one).
[ "${SECURE_BOOT}" = "true" ] || AMI_NAME="${AMI_NAME}-nosb"
SNAPSHOT_DESC="${ID}-${ARCH}-${VERSION_ID}-${BUILD_ID}"   # snapshot is SB-independent
AMI_DESC="${PRETTY_NAME} build: ${BUILD_ID}"

# ---- create the EBS snapshot directly from the raw boot disk (EBS Direct API) ----
# coldsnap writes the raw boot.disk's blocks straight into a snapshot in seconds, with
# no VMDK conversion, no S3 bucket, and no vmimport role. VM Import (the old path) was a
# slow batch service: minutes of fixed overhead regardless of disk size. Idempotent: a
# prior snapshot tagged with this BUILD_ID is reused.
echo "=== Checking for existing snapshot ==="
EXISTING_SNAPSHOT=$(aws ec2 describe-snapshots --region "${REGION}" --owner-ids self \
    --filters "Name=tag:BuildID,Values=${BUILD_ID}" \
    --query 'Snapshots[0].SnapshotId' --output text 2>/dev/null || echo "None")

if [ "${EXISTING_SNAPSHOT}" != "None" ] && [ -n "${EXISTING_SNAPSHOT}" ] && [ "${EXISTING_SNAPSHOT}" != "null" ]; then
    echo "Found existing snapshot: ${EXISTING_SNAPSHOT}"
    SNAPSHOT_ID="${EXISTING_SNAPSHOT}"
else
    echo "Uploading ${IMAGE_FILE} to a new EBS snapshot via coldsnap..."
    # --omit-zero-blocks keeps it sparse (the boot disk is mostly empty; EBS returns
    # zeros for absent blocks and the disk is unencrypted, so this is safe). --wait
    # blocks until the snapshot is 'completed'. Region comes from AWS_REGION.
    UPLOAD_OUT=$(AWS_REGION="${REGION}" coldsnap upload --wait --omit-zero-blocks "${IMAGE_FILE}") \
        || die "coldsnap upload failed (needs ebs:StartSnapshot/PutSnapshotBlock/CompleteSnapshot)"
    SNAPSHOT_ID=$(printf '%s\n' "${UPLOAD_OUT}" | grep -oE 'snap-[0-9a-f]+' | head -1)
    [ -n "${SNAPSHOT_ID}" ] || die "coldsnap upload returned no snapshot id (output: ${UPLOAD_OUT})"
    echo "Snapshot created: ${SNAPSHOT_ID}"
    aws ec2 create-tags --region "${REGION}" --resources "${SNAPSHOT_ID}" \
        --tags "Key=Name,Value=${SNAPSHOT_DESC}" "Key=BuildID,Value=${BUILD_ID}" "Key=VersionID,Value=${VERSION_ID}"
fi
record "aws snapshot ${REGION} ${SNAPSHOT_ID}"

echo "=== Checking for existing AMI ==="
EXISTING_AMI=$(aws ec2 describe-images --region "${REGION}" --owners self \
    --filters "Name=name,Values=${AMI_NAME}" --query 'Images[0].ImageId' --output text 2>/dev/null || echo "None")

if [ "${EXISTING_AMI}" != "None" ] && [ -n "${EXISTING_AMI}" ] && [ "${EXISTING_AMI}" != "null" ]; then
    echo "Found existing AMI: ${EXISTING_AMI}"
    AMI_ID="${EXISTING_AMI}"
else
    echo "Registering AMI from snapshot ${SNAPSHOT_ID}..."
    REG_ARGS=(
        --region "${REGION}"
        --name "${AMI_NAME}" --description "${AMI_DESC}" --architecture "${EC2_ARCH}"
        --root-device-name /dev/xvda --boot-mode uefi
        --tpm-support v2.0 --imds-support v2.0 --virtualization-type hvm --ena-support
        --block-device-mappings "DeviceName=/dev/xvda,Ebs={SnapshotId=${SNAPSHOT_ID}}"
    )
    if [ "${SECURE_BOOT}" = "true" ]; then
        # Enroll PK/KEK/db so the firmware boots in user mode with Secure Boot enforcing.
        REG_ARGS+=(--uefi-data "$(cat "${UEFI_DATA_FILE}")")
    else
        echo "WARNING: --no-secure-boot: registering WITHOUT enrolled keys (firmware in"
        echo "         setup mode, Secure Boot NOT enforced). Debug image only."
    fi
    AMI_ID=$(aws ec2 register-image "${REG_ARGS[@]}" --query 'ImageId' --output text) \
        || die "register-image failed"
    echo "AMI registered: ${AMI_ID}"
    aws ec2 create-tags --region "${REGION}" --resources "${AMI_ID}" \
        --tags "Key=Name,Value=${PRETTY_NAME}" "Key=BuildID,Value=${BUILD_ID}" "Key=VersionID,Value=${VERSION_ID}"
fi
record "aws ami ${REGION} ${AMI_ID}"

# Make the AMI publicly launchable (default; --private opts out): any AWS account
# can launch it directly (per-customer config lives in user-data, not the image).
# The backing snapshot is shared too so the public AMI can also be copied.
if [ "${PUBLIC}" = "true" ]; then
    echo "=== Making AMI publicly launchable ==="
    if aws ec2 modify-image-attribute --region "${REGION}" --image-id "${AMI_ID}" \
        --launch-permission "Add=[{Group=all}]"; then
        aws ec2 modify-snapshot-attribute --region "${REGION}" --snapshot-id "${SNAPSHOT_ID}" \
            --attribute createVolumePermission --operation-type add --group-names all || true
        echo "AMI ${AMI_ID} is now public (launchable by any AWS account)."
    else
        echo "WARN: could not make AMI public. If account-level public-AMI access is blocked:"
        echo "        aws ec2 disable-image-block-public-access --region ${REGION}"
        echo "      then re-run, or: aws ec2 modify-image-attribute --image-id ${AMI_ID} --launch-permission 'Add=[{Group=all}]' --region ${REGION}"
    fi
fi

echo ""
echo "=== AMI Created Successfully ==="
echo "AMI ID:       ${AMI_ID}"
echo "Region:       ${REGION}"
echo "Architecture: ${EC2_ARCH}"
echo ""

if [ "${ARCH}" = "aarch64" ]; then INSTANCE_TYPE="c7g.medium"; else INSTANCE_TYPE="c6i.large"; fi
echo "Launch an instance:"
echo "  aws ec2 run-instances --image-id ${AMI_ID} --instance-type ${INSTANCE_TYPE} --region ${REGION} --user-data file://config.json"
echo ""
echo "Launch with spot pricing (up to 90% cheaper):"
echo "  aws ec2 run-instances --image-id ${AMI_ID} --instance-type ${INSTANCE_TYPE} --region ${REGION} --user-data file://config.json \\"
echo "    --instance-market-options '{\"MarketType\":\"spot\",\"SpotOptions\":{\"SpotInstanceType\":\"one-time\"}}'"
echo ""
echo "Get serial console output:"
echo "  aws ec2 get-console-output --output text --latest --region ${REGION} --instance-id <instance-id>"

# Machine-readable result: the AMI ID on stdout (all the above went to stderr).
echo "${AMI_ID}" >&3
