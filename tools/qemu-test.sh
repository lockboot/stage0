#!/bin/bash
# stage0 QEMU test harness — a single, droppable script.
#
# Boots a disk image under QEMU with Secure Boot, an emulated TPM 2.0, a mocked
# EC2 IMDSv2 metadata service, and a local HTTP server for payloads. This is the
# canonical way to test that a UEFI payload boots, measures, and chain-loads under
# stage0; it is fully path-driven so any project can drop it in and point it at
# its own disk + user-data.
#
# Self-contained: it folds in TPM provisioning and downloads the EC2 metadata mock
# on first run (verified by sha256). The only external requirement is the runtime
# tooling (qemu, swtpm, dnsmasq, tpm2-tools, ovmf, python3, ip/iptables); see
# Dockerfile.harness for the canonical environment. Run privileged (it sets up a
# tap interface + iptables), so it is gated behind an explicit opt-in env var.
#
# Set HARNESS_DEBUG=1 for shell tracing.
set -euo pipefail
[ -n "${HARNESS_DEBUG:-}" ] && set -x

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
TMP=/tmp

# EC2 metadata mock (downloaded + sha256-verified on first run; cached next to the
# script, override the cache dir with EC2_MOCK_CACHE).
AEMM_VERSION="v1.13.0"
AEMM_URL="https://github.com/aws/amazon-ec2-metadata-mock/releases/download/${AEMM_VERSION}/ec2-metadata-mock-linux-amd64"
AEMM_SHA256="4f89ddc71ac53ce540bda1f9c340526d558eed8e41349761f2798acf1b254950"
EC2_MOCK_CACHE="${EC2_MOCK_CACHE:-${SCRIPT_DIR}}"
AMMM="${EC2_MOCK_CACHE}/ec2-metadata-mock-linux-amd64"

usage() {
    cat <<'EOF'
Usage: qemu-test.sh --boot-disk <path> --user-data <path> [OPTIONS]

Boot a disk under QEMU with Secure Boot + TPM 2.0 + a mocked EC2 IMDS, to test a
payload boots/measures/chain-loads under stage0.

Required:
  --boot-disk <path>       Disk image to boot (e.g. a stage0 boot.disk).
  --user-data <path>       Metadata user-data JSON served to the guest.

Options:
  --kind <stage0|uki>      Label for the boot banner (default: stage0). Does not
                           change behaviour; kept so consumers (e.g. the UKI
                           pipeline) can self-document their intent.
  --arch <x86_64|aarch64>  Guest architecture (default: $ARCH or x86_64).
  --ovmf-vars <path>       Secure Boot variables file. Default: efi-vars.ovmf next
                           to --boot-disk (build.sh emits both together).
  --payload <path>         Serve this file as http://10.0.2.1:8000/payload.efi
                           (a sibling <payload>.sig is served too if present).
  --serve-dir <path>       Serve this whole directory at http://10.0.2.1:8000/
                           instead of a single payload (e.g. UKI + stage2).
  --trace                  Capture guest TCP on tap0 to a pcap (see --trace-file).
  --trace-file <path>      pcap output path (default: ./stage0-trace.pcap).
  -h, --help               Show this help.

Requires the qemu/swtpm tooling present and privileged networking; set
YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 to confirm you are in a throwaway env
(a container, or a VM you do not mind reconfiguring tap0/iptables in).
EOF
}

ARCH="${ARCH:-x86_64}"
BOOT_KIND="stage0"
BOOT_DISK=""
USER_DATA=""
OVMF_VARS_OVERRIDE=""
PAYLOAD=""
SERVE_DIR=""
TRACE=0
TRACE_FILE=""

while [ $# -gt 0 ]; do
    case "$1" in
        --kind)       BOOT_KIND="$2"; shift 2 ;;
        --arch)       ARCH="$2"; shift 2 ;;
        --boot-disk)  BOOT_DISK="$2"; shift 2 ;;
        --user-data)  USER_DATA="$2"; shift 2 ;;
        --ovmf-vars)  OVMF_VARS_OVERRIDE="$2"; shift 2 ;;
        --payload)    PAYLOAD="$2"; shift 2 ;;
        --serve-dir)  SERVE_DIR="$2"; shift 2 ;;
        --trace)      TRACE=1; shift ;;
        --trace-file) TRACE_FILE="$2"; shift 2 ;;
        -h|--help)    usage; exit 0 ;;
        *) echo "Unknown option: $1" >&2; usage; exit 1 ;;
    esac
done

# --- Validation -------------------------------------------------------------
if [ "${YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES:-}" != 1 ]; then
    echo "Error: this sets up tap0 + iptables; refusing to run on an unconfirmed host." >&2
    echo "Set YES_INSIDE_DOCKER_DO_DANGEROUS_IPTABLES=1 (run inside the harness container)." >&2
    exit 1
fi
case "${ARCH}" in x86_64|aarch64) ;; *) echo "Unsupported --arch: ${ARCH}" >&2; exit 1 ;; esac
[ -n "${BOOT_DISK}" ] || { echo "Error: --boot-disk is required." >&2; usage; exit 1; }
[ -n "${USER_DATA}" ] || { echo "Error: --user-data is required." >&2; usage; exit 1; }
[ -f "${BOOT_DISK}" ] || { echo "Error: boot disk '${BOOT_DISK}' not found." >&2; exit 1; }
[ -f "${USER_DATA}" ] || { echo "Error: user-data '${USER_DATA}' not found." >&2; exit 1; }
TRACE_FILE="${TRACE_FILE:-$(pwd)/stage0-trace.pcap}"

# --- Preflight: required runtime tooling ------------------------------------
preflight() {
    local missing=() qemu_bin
    [ "${ARCH}" = "x86_64" ] && qemu_bin=qemu-system-x86_64 || qemu_bin=qemu-system-aarch64
    for t in "${qemu_bin}" swtpm swtpm_ioctl tpm2_startup dnsmasq python3 ip iptables curl sha256sum openssl xxd; do
        command -v "$t" >/dev/null 2>&1 || missing+=("$t")
    done
    if [ "${#missing[@]}" -ne 0 ]; then
        echo "Error: missing required tools: ${missing[*]}" >&2
        echo "Install the qemu/swtpm runtime (see Dockerfile.harness) and retry." >&2
        exit 1
    fi
}
preflight

# --- Self-bootstrap the EC2 metadata mock -----------------------------------
ensure_ec2_mock() {
    if [ -x "${AMMM}" ] && echo "${AEMM_SHA256}  ${AMMM}" | sha256sum -c - >/dev/null 2>&1; then
        return
    fi
    echo "Downloading EC2 metadata mock ${AEMM_VERSION}..."
    curl -fsSL -o "${AMMM}.tmp" "${AEMM_URL}"
    echo "${AEMM_SHA256}  ${AMMM}.tmp" | sha256sum -c - || { rm -f "${AMMM}.tmp"; echo "ec2-mock sha256 mismatch" >&2; exit 1; }
    mv "${AMMM}.tmp" "${AMMM}"
    chmod +x "${AMMM}"
}
ensure_ec2_mock

# --- Provision the vTPM with GCP-style NV indices (folded-in) ----------------
# Starts its own swtpm (server+ctrl sockets, required for the tpm2-tools TCTI),
# writes the NV template + AK cert vaportpm expects, then shuts down so the main
# swtpm below can reopen the saved state for QEMU. Idempotent.
provision_tpm() {
    local state_dir="$1" sock="${TMP}/swtpm-provision-sock" work
    export TPM2TOOLS_TCTI="swtpm:path=${sock}"
    work=$(mktemp -d)
    swtpm socket --tpmstate "dir=${state_dir}" \
        --server "type=unixio,path=${sock}" \
        --ctrl "type=unixio,path=${sock}.ctrl" \
        --tpm2 --daemon
    sleep 1
    swtpm_ioctl --unix "${sock}.ctrl" -i
    tpm2_startup -c

    local NV_ECC_CERT=0x01c10002 NV_ECC_TEMPLATE=0x01c10003
    if tpm2_nvreadpublic ${NV_ECC_TEMPLATE} >/dev/null 2>&1; then
        echo "vTPM already provisioned, skipping."
        tpm2_shutdown; swtpm_ioctl --unix "${sock}.ctrl" -s; rm -rf "${work}"; return
    fi
    echo "Provisioning vTPM for GCP-style attestation..."
    (
        cd "${work}"
        # Hardcoded TPMT_PUBLIC: ECC nameAlg=SHA256, non-restricted ECDSA-SHA256 P256
        # (tpm2_createprimary can't make restricted ECC signing keys; empty unique).
        echo -n "0023000b00040072000000100018000b0003001000000000" | xxd -r -p > template.bin
        tpm2_nvdefine ${NV_ECC_TEMPLATE} -s 24 -a "ownerread|ownerwrite|authread|authwrite"
        tpm2_nvwrite ${NV_ECC_TEMPLATE} -i template.bin
        tpm2_createprimary -C e -G ecc:ecdsa-sha256 \
            -a 'fixedtpm|fixedparent|sensitivedataorigin|userwithauth|sign' -c ak.ctx
        tpm2_readpublic -c ak.ctx -f pem -o ak.pub.pem
        openssl ecparam -genkey -name prime256v1 -noout -out ca.key
        openssl req -new -x509 -key ca.key -out ca.crt -days 3650 -subj "/CN=LockBoot Test CA" -batch
        openssl req -new -key ca.key -subj "/CN=Test AK" -out ak.csr -batch
        openssl x509 -req -in ak.csr -CA ca.crt -CAkey ca.key \
            -force_pubkey ak.pub.pem -out ak.crt -days 3650 \
            -extfile <(echo "keyUsage=critical,digitalSignature") -CAcreateserial
        openssl x509 -in ak.crt -outform DER -out ak.crt.der
        tpm2_nvdefine ${NV_ECC_CERT} -s "$(stat -c%s ak.crt.der)" -a "ownerread|ownerwrite|authread|authwrite"
        tpm2_nvwrite ${NV_ECC_CERT} -i ak.crt.der
    )
    tpm2_flushcontext -t
    tpm2_shutdown
    swtpm_ioctl --unix "${sock}.ctrl" -s
    rm -rf "${work}"
    echo "vTPM provisioned."
}

# --- Architecture-specific QEMU + firmware ----------------------------------
if [ "${ARCH}" = "x86_64" ]; then
    OVMF_CODE="/usr/share/OVMF/OVMF_CODE_4M.secboot.fd"
    QEMU_CMD="qemu-system-x86_64"
    QEMU_MACHINE="-machine q35,smm=on"
    QEMU_CPU=""
    QEMU_EXTRA="-enable-kvm"
    QEMU_SERIAL="-serial none"
    QEMU_SERIAL_DEVICE="-device isa-serial,chardev=char0"
    TPM_DEVICE="tpm-tis"
    PFLASH_SECURE="-global driver=cfi.pflash01,property=secure,value=on"
else
    OVMF_CODE="/usr/share/AAVMF/AAVMF_CODE.fd"
    QEMU_CMD="qemu-system-aarch64"
    QEMU_MACHINE="-machine virt"
    QEMU_CPU="-cpu cortex-a72"
    QEMU_EXTRA=""
    QEMU_SERIAL="-serial none"
    QEMU_SERIAL_DEVICE="-device pci-serial,id=serial0,chardev=char0"
    TPM_DEVICE="tpm-tis-device"
    PFLASH_SECURE=""
fi
[ -f "${OVMF_CODE}" ] || { echo "Error: ${OVMF_CODE} not found (install ovmf / qemu-efi-aarch64)." >&2; exit 1; }

OVMF_VARS_ORIG="${OVMF_VARS_OVERRIDE:-$(dirname "${BOOT_DISK}")/efi-vars.ovmf}"
[ -f "${OVMF_VARS_ORIG}" ] || { echo "Error: Secure Boot vars '${OVMF_VARS_ORIG}' not found (pass --ovmf-vars)." >&2; exit 1; }
OVMF_VARS="${TMP}/efi-vars.ovmf"
cp "${OVMF_VARS_ORIG}" "${OVMF_VARS}"

echo "=== Booting ${BOOT_KIND} with Secure Boot + TPM 2.0 (${ARCH}) ==="
echo "Boot disk:  ${BOOT_DISK}"
echo "User-data:  ${USER_DATA}"

# --- vTPM: provision, then start the QEMU-facing swtpm ----------------------
mkdir -p "${TMP}/tpm-state"
provision_tpm "${TMP}/tpm-state"
swtpm socket --tpmstate "dir=${TMP}/tpm-state" \
    --ctrl "type=unixio,path=${TMP}/swtpm-sock" \
    --tpm2 --pid "file=${TMP}/swtpm.pid" --daemon
sleep 1

cleanup() {
    kill "$(cat ${TMP}/swtpm.pid 2>/dev/null)" 2>/dev/null || true
    kill "$(cat ${TMP}/ec2-mock.pid 2>/dev/null)" 2>/dev/null || true
    kill "$(cat ${TMP}/payload-http.pid 2>/dev/null)" 2>/dev/null || true
    kill "$(cat ${TMP}/tcpdump.pid 2>/dev/null)" 2>/dev/null || true
    if [ "${TRACE}" = 1 ] && [ -n "${OWNER_UID:-}" ] && [ -f "${TRACE_FILE}" ]; then
        chown "${OWNER_UID}:${OWNER_GID:-${OWNER_UID}}" "${TRACE_FILE}" 2>/dev/null || true
    fi
}
trap cleanup EXIT INT TERM

echo "Press Ctrl-A, then X to exit QEMU"

# --- Guest network: tap0 (10.0.2.1 gw + 169.254.169.254 IMDS), NAT out ------
ip tuntap add dev tap0 mode tap
ip link set tap0 up
ip addr add 10.0.2.1/24 dev tap0
ip addr add 169.254.169.254/24 dev tap0

if [ "${TRACE}" = 1 ]; then
    echo "Capturing tap0 TCP -> ${TRACE_FILE}"
    tcpdump -i tap0 -s 0 -U -w "${TRACE_FILE}" tcp 2>/dev/null &
    echo $! > "${TMP}/tcpdump.pid"
    sleep 0.5
fi

echo "Starting EC2 metadata mock (IMDSv2)..."
echo '{"userdata":{"values":{"userdata":"'"$(base64 -w0 "${USER_DATA}")"'"}}}' > "${TMP}/aemm-config.json"
"${AMMM}" --imdsv2 -n 169.254.169.254 --port 80 --config-file "${TMP}/aemm-config.json" &
echo $! > "${TMP}/ec2-mock.pid"
sleep 1

# Serve a local tree over HTTP on the tap gateway so user-data can point at
# http://10.0.2.1:8000/<file>. --serve-dir serves a directory; --payload wraps a
# single file as /payload.efi (+ /payload.efi.sig if present).
SERVE_ROOT=""
if [ -n "${SERVE_DIR}" ]; then
    [ -d "${SERVE_DIR}" ] || { echo "Error: serve-dir ${SERVE_DIR} not found" >&2; exit 1; }
    SERVE_ROOT="${SERVE_DIR}"
elif [ -n "${PAYLOAD}" ]; then
    [ -f "${PAYLOAD}" ] || { echo "Error: payload ${PAYLOAD} not found" >&2; exit 1; }
    SERVE_ROOT=$(mktemp -d)
    cp "${PAYLOAD}" "${SERVE_ROOT}/payload.efi"
    [ -f "${PAYLOAD}.sig" ] && cp "${PAYLOAD}.sig" "${SERVE_ROOT}/payload.efi.sig"
fi
if [ -n "${SERVE_ROOT}" ]; then
    # HTTP/1.1 (Content-Length + keep-alive). The stdlib default is HTTP/1.0
    # Connection: close, which OVMF's HttpDxe never completes the response token for.
    ( cd "${SERVE_ROOT}" && exec python3 -c 'import http.server; http.server.SimpleHTTPRequestHandler.protocol_version="HTTP/1.1"; http.server.ThreadingHTTPServer(("10.0.2.1",8000), http.server.SimpleHTTPRequestHandler).serve_forever()' ) &
    echo $! > "${TMP}/payload-http.pid"
    echo "Serving ${SERVE_ROOT} (HTTP/1.1) at http://10.0.2.1:8000/ :"
    ls -l "${SERVE_ROOT}" | sed 's/^/  /'
fi

echo 1 > /proc/sys/net/ipv4/ip_forward
iptables -t nat -A POSTROUTING -o eth0 -j MASQUERADE

# dnsmasq: EC2-style DHCP/DNS (gateway, DNS, classless route to IMDS, hostnames),
# plus payload.lockboot.test -> 10.0.2.1 so hostname URLs exercise EFI_DNS4.
{
    for i in $(seq 10 20); do echo "10.0.2.${i} ip-10-0-2-${i}"; done
    echo "10.0.2.1 payload.lockboot.test"
} > "${TMP}/dnsmasq-hosts"
dnsmasq --interface=tap0 --bind-interfaces \
    --dhcp-range=10.0.2.10,10.0.2.20,12h \
    --dhcp-option=3,10.0.2.1 \
    --dhcp-option=6,10.0.2.1,8.8.8.8 \
    --dhcp-option=15,ec2.internal \
    --dhcp-option=option:classless-static-route,169.254.169.254/32,10.0.2.1 \
    --dhcp-option=119,ec2.internal,local.compute.internal \
    --domain=ec2.internal \
    --expand-hosts \
    --addn-hosts="${TMP}/dnsmasq-hosts" \
    --log-queries

# shellcheck disable=SC2086
${QEMU_CMD} \
    ${QEMU_CPU} \
    ${QEMU_EXTRA} \
    ${QEMU_MACHINE} \
    ${PFLASH_SECURE} \
    -smp cores=2,threads=1 -m 512 \
    -object rng-random,filename=/dev/urandom,id=rng0 \
    -device virtio-rng-pci,rng=rng0 \
    -chardev "socket,id=chrtpm,path=${TMP}/swtpm-sock" \
    -tpmdev emulator,id=tpm0,chardev=chrtpm \
    -device ${TPM_DEVICE},tpmdev=tpm0 \
    -drive "file=${BOOT_DISK},format=raw,if=none,id=boot" \
    -device nvme,serial=boot,drive=boot,bootindex=0 \
    -netdev tap,id=net0,ifname=tap0,script=no \
    -device virtio-net-pci,netdev=net0 \
    -display none \
    ${QEMU_SERIAL} \
    -chardev stdio,mux=on,id=char0 \
    ${QEMU_SERIAL_DEVICE} \
    -drive "if=pflash,format=raw,unit=0,file=${OVMF_CODE},readonly=on" \
    -drive "if=pflash,format=raw,unit=1,file=${OVMF_VARS}" || true
