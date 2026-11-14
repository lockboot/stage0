#!/bin/bash
# Script to fetch serial console output from a Confidential VM instance
# Usage: ./get-console.sh <instance-name> <zone> [options]

set -euo pipefail

# Find gcloud: check local installation first, then system
SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
if [ -x "${SCRIPT_DIR}/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/gcloud"
elif [ -x "${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud" ]; then
    GCLOUD="${SCRIPT_DIR}/google-cloud-sdk/bin/gcloud"
elif command -v gcloud &> /dev/null; then
    GCLOUD="gcloud"
else
    echo "Error: gcloud not found. Install it with:"
    echo "  ./install-gcloud.sh"
    exit 1
fi

if [ $# -lt 2 ]; then
    echo "Usage: $0 <instance-name> <zone> [--follow|--tail N]"
    echo ""
    echo "Examples:"
    echo "  # Get full console output"
    echo "  $0 my-vm us-central1-a"
    echo ""
    echo "  # Get last 50 lines"
    echo "  $0 my-vm us-central1-a --tail 50"
    echo ""
    echo "  # Follow console output (poll every 2 seconds)"
    echo "  $0 my-vm us-central1-a --follow"
    echo ""
    echo "Useful for viewing stage2 attestation output dumped to console"
    echo ""
    echo "Documentation:"
    echo "  https://cloud.google.com/compute/docs/troubleshooting/viewing-serial-port-output"
    exit 1
fi

INSTANCE_NAME="$1"
ZONE="$2"
MODE="${3:-full}"

# Get current project
PROJECT=$(${GCLOUD} config get-value project 2>/dev/null || echo "")
if [ -z "${PROJECT}" ]; then
    echo "Error: No default project set. Run: ${GCLOUD} config set project <project-id>"
    exit 1
fi

case "${MODE}" in
    --follow)
        echo "Following console output for ${INSTANCE_NAME} (Ctrl+C to stop)..."
        echo "---"

        # --start is a BYTE index; resume from the `next` offset each response reports (it also
        # stays correct if the serial buffer rolled over and older bytes were dropped).
        # Every gcloud call is a full Python start-up (~1s of CPU), so poll every 10s, and only
        # when a poll brings nothing new ask for the instance status: once it is no longer
        # RUNNING (stage0 powered off / stopped / deleted) do one last read and exit, instead of
        # polling a dead instance forever.
        command -v jq >/dev/null 2>&1 || { echo "Error: --follow needs jq"; exit 1; }
        NEXT=0
        read_once() {
            local resp n got=1
            resp=$(${GCLOUD} compute instances get-serial-port-output "${INSTANCE_NAME}" \
                --zone="${ZONE}" \
                --project="${PROJECT}" \
                --start="${NEXT}" --format=json 2>/dev/null || echo "")
            if [ -n "${resp}" ]; then
                jq -j '.contents // ""' <<<"${resp}"
                n=$(jq -r '.next // empty' <<<"${resp}")
                if [ -n "${n}" ] && [ "${n}" != "${NEXT}" ]; then NEXT="${n}"; got=0; fi
            fi
            return "${got}"
        }
        while true; do
            if ! read_once; then
                STATUS=$(${GCLOUD} compute instances describe "${INSTANCE_NAME}" \
                    --zone="${ZONE}" --project="${PROJECT}" \
                    --format="value(status)" 2>/dev/null || echo "GONE")
                if [ "${STATUS:-GONE}" != "RUNNING" ] && [ "${STATUS}" != "PROVISIONING" ] \
                    && [ "${STATUS}" != "STAGING" ]; then
                    read_once || true
                    echo
                    echo "--- ${INSTANCE_NAME} is ${STATUS:-GONE}; stopped following ---"
                    exit 0
                fi
            fi
            sleep 10
        done
        ;;

    --tail)
        if [ $# -lt 4 ]; then
            echo "Error: --tail requires a line count"
            echo "Example: $0 ${INSTANCE_NAME} ${ZONE} --tail 50"
            exit 1
        fi

        LINES="$4"
        ${GCLOUD} compute instances get-serial-port-output "${INSTANCE_NAME}" \
            --zone="${ZONE}" \
            --project="${PROJECT}" | tail -n "${LINES}"
        ;;

    *)
        # Full output
        ${GCLOUD} compute instances get-serial-port-output "${INSTANCE_NAME}" \
            --zone="${ZONE}" \
            --project="${PROJECT}"
        ;;
esac
