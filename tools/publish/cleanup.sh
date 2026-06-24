#!/bin/bash
# Tear down cloud resources recorded in a --manifest file written by the
# ec2/gcp create.sh scripts. The manifest is processed in REVERSE order so an AMI is
# deregistered before its snapshot is deleted. Delete failures (already-gone, or a
# snapshot still settling) are warnings, not fatal, so this is safe to re-run.
#
# Manifest line format: "<provider> <kind> <region-or-project> <id-or-uri>"
#   aws ami       <region>   ami-xxxx
#   aws snapshot  <region>   snap-xxxx
#   aws s3object  <region>   s3://bucket/key
#   gcp image     <project>  image-name
#   gcp gcsobject <project>  gs://bucket/path

set -euo pipefail

die()  { echo "Error: $*" >&2; exit 1; }
warn() { echo "WARN: $*" >&2; }

usage() {
    cat <<EOF
Usage: $(basename "$0") [--dry-run] <manifest-file>

Delete the cloud resources listed in <manifest-file> (written by the publish
scripts' --manifest flag), bottom-to-top so AMIs deregister before their snapshots.

Options:
  --dry-run    print the delete commands without running them
  -h, --help   show this help and exit

Handles: aws {ami,snapshot,s3object}, gcp {image,gcsobject}.
EOF
}

DRY_RUN=false
MANIFEST=""
while [ $# -gt 0 ]; do
    case "$1" in
        --dry-run) DRY_RUN=true; shift ;;
        -h|--help) usage; exit 0 ;;
        --) shift; [ $# -gt 0 ] && { MANIFEST="$1"; shift; } ;;
        -*) echo "Error: unknown option: $1" >&2; usage; exit 1 ;;
        *)  MANIFEST="$1"; shift ;;
    esac
done

[ -n "${MANIFEST}" ] || { usage; exit 1; }
[ -f "${MANIFEST}" ] || die "manifest not found: ${MANIFEST}"

mapfile -t LINES < "${MANIFEST}"

deleted=0; failed=0; skipped=0
for (( i=${#LINES[@]}-1; i>=0; i-- )); do
    line="${LINES[i]}"
    case "${line}" in ""|\#*) continue ;; esac          # skip blanks / comments
    read -r provider kind ctx id _ <<<"${line}"
    [ -n "${id:-}" ] || { warn "malformed line: ${line}"; skipped=$((skipped+1)); continue; }

    case "${provider} ${kind}" in
        "aws ami")       cli=aws;    cmd=(aws ec2 deregister-image --image-id "${id}" --region "${ctx}") ;;
        "aws snapshot")  cli=aws;    cmd=(aws ec2 delete-snapshot --snapshot-id "${id}" --region "${ctx}") ;;
        "aws s3object")  cli=aws;    cmd=(aws s3 rm "${id}") ;;
        "gcp image")     cli=gcloud; cmd=(gcloud compute images delete "${id}" --project "${ctx}" --quiet) ;;
        "gcp gcsobject") cli=gcloud; cmd=(gcloud storage rm "${id}" --project "${ctx}") ;;
        *) warn "unknown resource: ${line}"; skipped=$((skipped+1)); continue ;;
    esac

    if [ "${DRY_RUN}" = "true" ]; then
        echo "[dry-run] ${cmd[*]}"
        continue
    fi

    if ! command -v "${cli}" >/dev/null 2>&1; then
        warn "skip (${cli} not installed): ${provider} ${kind} ${id}"; skipped=$((skipped+1)); continue
    fi

    echo "Deleting ${provider} ${kind}: ${id}"
    if "${cmd[@]}"; then
        deleted=$((deleted+1))
    else
        warn "delete failed (already gone, or in use?): ${provider} ${kind} ${id}"
        failed=$((failed+1))
    fi
done

if [ "${DRY_RUN}" = "true" ]; then
    echo "Dry run complete (no changes)."
else
    echo "Done: ${deleted} deleted, ${failed} failed, ${skipped} skipped."
fi
