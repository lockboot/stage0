#!/bin/bash
# Create a GCP custom image from a stage0 boot disk (one-shot). The GCS bucket is
# the os-release ID. The image is made publicly launchable unless --private is given.
#
# All progress goes to stderr; the created image name is printed to stdout, so it can
# be captured:  IMG=$(create.sh x86_64)  then
# launch-instance.sh my-vm <zone> <type> "$IMG" config.json

set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1${2:+ ($2)}"; }
# Append a created-resource line to the manifest (if --manifest was given).
record() { [ -n "${MANIFEST:-}" ] || return 0; printf '%s\n' "$*" >> "${MANIFEST}"; }

DEFAULT_REGION="asia-southeast1"   # GCP Singapore

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] <arch> [version]

Build (or download) a stage0 boot disk and create a GCP image from it.

Arguments:
  arch       x86_64 | aarch64
  version    a stage0-v* release tag, or 'local' (default) for a local build

Options:
  --project <p>  GCP project (default: active gcloud project)
  --region <r>   GCS bucket / zone region (default: ${DEFAULT_REGION})
  --public       make the image usable by any authenticated GCP user (default)
  --private      keep the image private to this project
  --no-verify    (release mode) skip gh attestation; fetch the public release asset
                 via curl so no gh install is needed
  --manifest <f>  append created resources to <f> for a teardown script, one per
                  line: "gcp <kind> <project> <id-or-uri>" (gcsobject, image)
  -h, --help     show this help and exit

Examples:
  $(basename "$0") x86_64                          # active project, public image in ${DEFAULT_REGION}
  $(basename "$0") --project my-proj x86_64 stage0-v0.1.0
  $(basename "$0") --private aarch64
EOF
}

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

PROJECT=""
REGION="${DEFAULT_REGION}"
PUBLIC=true
NO_VERIFY=false
MANIFEST=""
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --project)    PROJECT="${2:?--project needs a value}"; shift 2 ;;
        --project=*)  PROJECT="${1#*=}"; shift ;;
        --region)     REGION="${2:?--region needs a value}"; shift 2 ;;
        --region=*)   REGION="${1#*=}"; shift ;;
        --public)     PUBLIC=true; shift ;;
        --private)    PUBLIC=false; shift ;;
        --no-verify)  NO_VERIFY=true; shift ;;
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
case "${ARCH}" in aarch64) GCP_ARCH="ARM64" ;; *) GCP_ARCH="X86_64" ;; esac

# Find gcloud: local install first, then system.
if [ -x "${SCRIPT_DIR}/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/gcloud"
elif [ -x "${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud"
elif command -v gcloud >/dev/null 2>&1; then
    GCLOUD="gcloud"
else
    die "gcloud not found. Install it with: ${SCRIPT_DIR}/install-gcloud.sh"
fi

# ---- preflight: authenticated account + a resolvable project ----
${GCLOUD} auth list --filter=status:ACTIVE --format="value(account)" 2>/dev/null | grep -q . \
    || die "no active gcloud account; run: ${GCLOUD} auth login"
[ -n "${PROJECT}" ] || PROJECT=$(${GCLOUD} config get-value project 2>/dev/null || echo "")
[ -n "${PROJECT}" ] || die "no project (pass --project or run: ${GCLOUD} config set project <id>)"

CLEANUP=()
cleanup() { local p; for p in "${CLEANUP[@]:-}"; do [ -n "$p" ] && rm -rf "$p"; done; }
trap cleanup EXIT

# Save real stdout on fd 3 and route everything else to stderr, so the only thing
# on stdout is the final image name (printed via >&3). Command substitutions are
# unaffected. Done after --help/arg parsing so usage still prints to stdout.
exec 3>&1 1>&2

# ---- resolve the boot disk + Secure Boot certs: local build or verified release ----
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
OS_RELEASE_FILE="${WORK_DIR}/os-release"
# Secure Boot certs: from the extracted release (flat), else the local keys dir.
if [ -f "${WORK_DIR}/db.cer" ]; then
    KEYS_DIR="${WORK_DIR}"
else
    KEYS_DIR="$(cd "${SCRIPT_DIR}/../../.." && pwd)/build/keys"
fi

[ -f "${OS_RELEASE_FILE}" ] || die "os-release not found: ${OS_RELEASE_FILE} (build it: make build-${ARCH})"
[ -f "${IMAGE_FILE}" ]      || die "boot.disk not found: ${IMAGE_FILE} (build it: make build-${ARCH})"
for c in PK KEK db; do
    [ -f "${KEYS_DIR}/${c}.cer" ] || die "Secure Boot cert ${c}.cer not found in ${KEYS_DIR}"
done

# os-release provides ID, VERSION_ID, BUILD_ID, NAME, PRETTY_NAME (our own artifact).
# shellcheck disable=SC1090
source "${OS_RELEASE_FILE}"

VERSION_DASH=$(echo "${VERSION_ID}" | tr '.' '-')
ARCH_DASH=$(echo "${ARCH}" | tr '_' '-')
IMAGE_NAME="${ID}-${ARCH_DASH}-${VERSION_DASH}"           # GCP names: lowercase/digits/hyphens
IMAGE_DESC="${PRETTY_NAME} version: ${VERSION_ID} build: ${BUILD_ID} arch: ${ARCH}"
IMAGE_FAMILY="${ID}"

if [ "${ARCH}" = "x86_64" ]; then
    GUEST_OS_FEATURES="UEFI_COMPATIBLE,SEV_CAPABLE,SEV_SNP_CAPABLE,GVNIC"
else
    GUEST_OS_FEATURES="UEFI_COMPATIBLE,GVNIC"
fi

echo "=== Checking for existing image ==="
EXISTING_IMAGE=$(${GCLOUD} compute images list --project="${PROJECT}" \
    --filter="name=${IMAGE_NAME}" --format="value(name)" 2>/dev/null || echo "")

if [ -n "${EXISTING_IMAGE}" ]; then
    echo "Image already exists: ${EXISTING_IMAGE}"
    IMAGE_FINAL="${EXISTING_IMAGE}"
else
    GCS_BUCKET="${ID}"
    GCS_PATH="${VERSION_ID}/${BUILD_ID}.tar.gz"
    GCS_URI="gs://${GCS_BUCKET}/${GCS_PATH}"

    # Ensure the bucket exists in our region.
    if ${GCLOUD} storage buckets describe "gs://${GCS_BUCKET}" --project="${PROJECT}" &>/dev/null; then
        echo "Bucket exists: gs://${GCS_BUCKET}"
    else
        echo "Creating bucket gs://${GCS_BUCKET} in ${REGION}..."
        ${GCLOUD} storage buckets create "gs://${GCS_BUCKET}" --project="${PROJECT}" \
            --location="${REGION}" --uniform-bucket-level-access \
            || die "could not create bucket gs://${GCS_BUCKET} (name taken in another project?)"
    fi

    # GCP image source is a .tar.gz containing a sparse disk.raw.
    if ${GCLOUD} storage ls "${GCS_URI}" --project="${PROJECT}" &>/dev/null; then
        echo "Disk already in GCS: ${GCS_URI}"
    else
        TEMP_DIR=$(mktemp -d); CLEANUP+=("${TEMP_DIR}")
        echo "Packing disk.raw -> tar.gz (sparse)..."
        cp --sparse=always "${IMAGE_FILE}" "${TEMP_DIR}/disk.raw"
        tar --format=oldgnu -Sczf "${TEMP_DIR}/${BUILD_ID}.tar.gz" -C "${TEMP_DIR}" disk.raw
        echo "Uploading to ${GCS_URI} ..."
        ${GCLOUD} storage cp "${TEMP_DIR}/${BUILD_ID}.tar.gz" "${GCS_URI}" --project="${PROJECT}" \
            --custom-metadata="version-id=${VERSION_ID},build-id=${BUILD_ID},name=${NAME},pretty-name=${PRETTY_NAME},id=${ID},arch=${ARCH}" \
            || die "GCS upload failed"
    fi
    record "gcp gcsobject ${PROJECT} ${GCS_URI}"

    echo "=== Creating image ${IMAGE_NAME} (${GCP_ARCH}, ${GUEST_OS_FEATURES}) ==="
    ${GCLOUD} compute images create "${IMAGE_NAME}" --project="${PROJECT}" \
        --source-uri="${GCS_URI}" --guest-os-features="${GUEST_OS_FEATURES}" \
        --architecture="${GCP_ARCH}" --family="${IMAGE_FAMILY}" --description="${IMAGE_DESC}" \
        --platform-key-file="${KEYS_DIR}/PK.cer" \
        --key-exchange-key-file="${KEYS_DIR}/KEK.cer" \
        --signature-database-file="${KEYS_DIR}/db.cer" \
        || die "image create failed"
    IMAGE_FINAL="${IMAGE_NAME}"
fi
record "gcp image ${PROJECT} ${IMAGE_FINAL}"

# Make the image publicly launchable (default; --private opts out): any authenticated
# GCP user can create instances from it (per-customer config lives in user-data).
if [ "${PUBLIC}" = "true" ]; then
    echo "=== Making image publicly launchable ==="
    if ${GCLOUD} compute images add-iam-policy-binding "${IMAGE_FINAL}" --project="${PROJECT}" \
        --member="allAuthenticatedUsers" --role="roles/compute.imageUser"; then
        echo "Image ${IMAGE_FINAL} is now usable by any authenticated GCP user."
    else
        echo "WARN: could not set public IAM on ${IMAGE_FINAL} (an org policy may forbid public sharing)."
    fi
fi

echo ""
echo "=== Image Created Successfully ==="
echo "Image:        ${IMAGE_FINAL}"
echo "Project:      ${PROJECT}"
echo "Family:       ${IMAGE_FAMILY}"
echo "Architecture: ${GCP_ARCH}"
echo ""

DEFAULT_ZONE=$(${GCLOUD} config get-value compute/zone 2>/dev/null || echo "")
[ -n "${DEFAULT_ZONE}" ] || DEFAULT_ZONE="${REGION}-a"
if [ "${ARCH}" = "aarch64" ]; then MACHINE_TYPE="t2a-standard-1"; TECH="ARM TrustZone"; else MACHINE_TYPE="n2d-standard-2"; TECH="AMD SEV-SNP"; fi

echo "Launch a Confidential VM (${TECH}):"
echo "  ${SCRIPT_DIR}/launch-instance.sh my-instance ${DEFAULT_ZONE} ${MACHINE_TYPE} ${IMAGE_FINAL} config.json"
echo ""
echo "Default zone: ${DEFAULT_ZONE} (override: ${GCLOUD} config set compute/zone <zone>)"

# Machine-readable result: the image name on stdout (all the above went to stderr).
echo "${IMAGE_FINAL}" >&3
