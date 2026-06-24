#!/bin/bash
# Launch a stage0 AMI with a _stage1 user-data config, optionally on spot, and
# optionally tail its serial console until the instance powers off.
#
# The AMI already carries the UEFI/TPM-v2/Secure-Boot settings (set at register
# time by create.sh), so launching is just run-instances + user-data. stage0 is
# the root of trust and powers the machine OFF when it is done (fail-closed).
#
# Default shutdown behavior is TERMINATE: these are ephemeral test instances, so the
# box self-destructs when stage0 powers off. Pass --stop to keep it (a stopped
# instance retains its serial console, which is what you want to debug a fast-failing
# boot). A one-time spot instance can't stop, so --stop is ignored under --spot.
#
# The launched instance ID is printed to stdout; progress goes to stderr.

set -euo pipefail

die() { echo "Error: $*" >&2; exit 1; }
require_cmd() { command -v "$1" >/dev/null 2>&1 || die "required command not found: $1${2:+ ($2)}"; }

DEFAULT_REGION="ap-southeast-1"   # AWS Singapore (matches create.sh)
NAME="stage0-test"

usage() {
    cat <<EOF
Usage: $(basename "$0") [options] <ami-id> <config-file>

Launch a stage0 AMI with a _stage1 user-data document.

Arguments:
  ami-id       the AMI to launch (e.g. from: AMI=\$(create.sh x86_64))
  config-file  _stage1 user-data JSON passed as --user-data

Options:
  --region <r>         AWS region (default: ${DEFAULT_REGION})
  --instance-type <t>  override the instance type (default: derived from the AMI
                       architecture -- c6i.large for x86_64, c7g.medium for arm64)
  --name <n>           Name tag for the instance (default: ${NAME})
  --spot               request a spot instance (up to ~90% cheaper). NOTE: a one-time
                       spot instance cannot stop, so it always TERMINATES on poweroff
                       and its console log is lost -- omit --spot when debugging a boot.
  --tail               stream the serial console until the instance powers off,
                       including a post-mortem drain (EC2's serial buffer lags minutes)
  --stop               STOP (don't terminate) on shutdown, so the instance and its
                       serial console survive for debugging. Default is to terminate.
  -h, --help           show this help and exit

Examples:
  AMI=\$(./create.sh x86_64)
  $(basename "$0") --tail "\$AMI" config.json
  $(basename "$0") --spot --region ap-southeast-1 "\$AMI" config.json
EOF
}

REGION="${DEFAULT_REGION}"
INSTANCE_TYPE=""
SPOT=false
TAIL=false
STOP=false
POSITIONAL=()
while [ $# -gt 0 ]; do
    case "$1" in
        --region)          REGION="${2:?--region needs a value}"; shift 2 ;;
        --region=*)        REGION="${1#*=}"; shift ;;
        --instance-type)   INSTANCE_TYPE="${2:?--instance-type needs a value}"; shift 2 ;;
        --instance-type=*) INSTANCE_TYPE="${1#*=}"; shift ;;
        --name)            NAME="${2:?--name needs a value}"; shift 2 ;;
        --name=*)          NAME="${1#*=}"; shift ;;
        --spot)            SPOT=true; shift ;;
        --tail)            TAIL=true; shift ;;
        --stop)            STOP=true; shift ;;
        -h|--help)         usage; exit 0 ;;
        --) shift; while [ $# -gt 0 ]; do POSITIONAL+=("$1"); shift; done ;;
        -*) echo "Error: unknown option: $1" >&2; usage; exit 1 ;;
        *)  POSITIONAL+=("$1"); shift ;;
    esac
done
set -- "${POSITIONAL[@]}"
[ $# -ge 2 ] || { usage; exit 1; }

AMI_ID="$1"
CONFIG_FILE="$2"

# ---- preflight ----
require_cmd aws "install the AWS CLI"
[ -f "${CONFIG_FILE}" ] || die "config file not found: ${CONFIG_FILE}"
aws sts get-caller-identity >/dev/null 2>&1 \
    || die "AWS credentials not working (aws sts get-caller-identity failed); run 'aws configure' or set AWS_PROFILE"

exec 3>&1 1>&2

# Resolve the AMI architecture to pick a sensible default instance type, and to
# fail early if the AMI ID is wrong/not visible in this region.
ARCH=$(aws ec2 describe-images --region "${REGION}" --image-ids "${AMI_ID}" \
    --query 'Images[0].Architecture' --output text 2>/dev/null || echo "")
[ -n "${ARCH}" ] && [ "${ARCH}" != "None" ] \
    || die "AMI ${AMI_ID} not found in ${REGION} (wrong region, or not shared with this account?)"
if [ -z "${INSTANCE_TYPE}" ]; then
    case "${ARCH}" in
        arm64)  INSTANCE_TYPE="c7g.medium" ;;
        x86_64) INSTANCE_TYPE="c6i.large" ;;
        *)      die "unexpected AMI architecture '${ARCH}'; pass --instance-type" ;;
    esac
fi

# Default: TERMINATE on shutdown (ephemeral test box). --stop keeps it so its console
# log survives a fast-failing boot. A one-time spot instance cannot stop, so --stop is
# forced back to terminate; warn that the console will be lost.
SHUTDOWN_BEHAVIOR="terminate"; if [ "${STOP}" = "true" ]; then SHUTDOWN_BEHAVIOR="stop"; fi
if [ "${SPOT}" = "true" ] && [ "${SHUTDOWN_BEHAVIOR}" = "stop" ]; then
    echo "WARN: a one-time spot instance can't stop; it will TERMINATE on poweroff and"
    echo "      the serial console log will be lost. Omit --spot to keep --stop effective."
    SHUTDOWN_BEHAVIOR="terminate"
fi

RUN_ARGS=(
    --region "${REGION}"
    --image-id "${AMI_ID}"
    --instance-type "${INSTANCE_TYPE}"
    --user-data "file://${CONFIG_FILE}"
    --instance-initiated-shutdown-behavior "${SHUTDOWN_BEHAVIOR}"
    --tag-specifications "ResourceType=instance,Tags=[{Key=Name,Value=${NAME}}]"
)
if [ "${SPOT}" = "true" ]; then
    RUN_ARGS+=(--instance-market-options '{"MarketType":"spot","SpotOptions":{"SpotInstanceType":"one-time"}}')
fi

MARKET=""; if [ "${SPOT}" = "true" ]; then MARKET=" [spot]"; fi
echo "=== Launching ${AMI_ID} (${ARCH}) as ${INSTANCE_TYPE} in ${REGION}${MARKET} ==="
INSTANCE_ID=$(aws ec2 run-instances "${RUN_ARGS[@]}" \
    --query 'Instances[0].InstanceId' --output text) || die "run-instances failed"
echo "Launched instance ${INSTANCE_ID} (Name=${NAME}, shutdown=${SHUTDOWN_BEHAVIOR})"

if [ "${TAIL}" = "true" ]; then
    # Do NOT use `aws ec2 wait instance-running`: stage0 can boot, run, and power off
    # in seconds, so the instance may skip straight past 'running' to 'shutting-down'
    # and the waiter would treat that as a failure. Instead poll state ourselves and
    # stream the console regardless of whether we ever caught it 'running'.
    # Probe the system-log API once: if the identity lacks ec2:GetConsoleOutput we'd
    # otherwise just tail nothing forever. Surface the real reason and keep watching
    # state (the instance still runs; you can fetch the log later with the right perms).
    PROBE_ERR=$(mktemp); CLEANUP+=("${PROBE_ERR}")
    CONSOLE_OK=true
    if ! aws ec2 get-console-output --region "${REGION}" --instance-id "${INSTANCE_ID}" \
        --latest --output text --query 'Output' >/dev/null 2>"${PROBE_ERR}"; then
        if grep -qiE 'AccessDenied|UnauthorizedOperation|not authorized' "${PROBE_ERR}"; then
            CONSOLE_OK=false
            echo "WARN: this identity can't read the system log (ec2:GetConsoleOutput denied)."
            echo "      Grant ec2:GetConsoleOutput, then fetch it yourself once booted:"
            echo "        aws ec2 get-console-output --region ${REGION} --instance-id ${INSTANCE_ID} --latest --output text"
            echo "      (That is the system-log API; the interactive EC2 Serial Console is a"
            echo "       separate feature needing account enablement + ec2-instance-connect perms.)"
        fi
        # A not-yet-available console (empty/booting) is fine; only perms turn it off.
    fi

    if [ "${CONSOLE_OK}" = "true" ]; then
        echo "Watching ${INSTANCE_ID} (serial console lags minutes on EC2; Ctrl-C to stop)..."
        echo "--- serial console: ${INSTANCE_ID} ---"
    else
        echo "Watching ${INSTANCE_ID} state only (no console access; Ctrl-C to stop)..."
    fi
    PREV=""
    DRAIN=0          # extra console fetches after the instance is gone (buffer lags)
    DRAIN_MAX=12     # ~2 min of post-mortem draining at 10s/poll
    while :; do
        STATE=$(aws ec2 describe-instances --region "${REGION}" --instance-ids "${INSTANCE_ID}" \
            --query 'Reservations[0].Instances[0].State.Name' --output text 2>/dev/null || echo "unknown")
        # --latest returns the whole console buffer; print only the newly-appended tail.
        CUR=""
        if [ "${CONSOLE_OK}" = "true" ]; then
            CUR=$(aws ec2 get-console-output --region "${REGION}" --instance-id "${INSTANCE_ID}" \
                --latest --output text --query 'Output' 2>/dev/null || echo "")
        fi
        if [ -n "${CUR}" ] && [ "${CUR}" != "None" ] && [ "${CUR}" != "${PREV}" ]; then
            if [ -n "${PREV}" ] && [ "${CUR}" != "${CUR#"${PREV}"}" ]; then
                printf '%s' "${CUR#"${PREV}"}"   # grew by appending: emit the delta
            else
                printf '%s' "${CUR}"             # buffer rotated/first fetch: emit all
            fi
            echo
            PREV="${CUR}"
        fi
        case "${STATE}" in
            stopped|terminated|shutting-down)
                # The box is going/gone, but EC2's serial buffer flushes late: keep
                # fetching for a couple minutes so a fast-failing boot's log still lands.
                # Nothing to drain if we have no console access -- announce and stop.
                [ "${CONSOLE_OK}" = "true" ] || DRAIN_MAX=1
                DRAIN=$((DRAIN + 1))
                if [ "${DRAIN}" -ge "${DRAIN_MAX}" ]; then
                    echo "--- instance ${STATE}; console drain finished ---"
                    if [ "${STATE}" = "terminated" ]; then
                        echo "(terminated: console output is no longer retained. Re-run with --stop (and without --spot) to keep it.)"
                    elif [ "${STATE}" = "stopped" ]; then
                        echo "Instance is stopped (retained). Full log later: aws ec2 get-console-output --region ${REGION} --instance-id ${INSTANCE_ID} --latest --output text"
                        echo "Clean it up when done:               aws ec2 terminate-instances --region ${REGION} --instance-ids ${INSTANCE_ID}"
                    fi
                    break
                fi
                sleep 10
                continue ;;
        esac
        sleep 10
    done
fi

echo "${INSTANCE_ID}" >&3
