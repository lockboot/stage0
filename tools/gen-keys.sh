#!/bin/bash
# Generate stage0's snakeoil Secure Boot keys (PK, KEK, db) into a directory.
# These are ephemeral test/enrollment keys, regenerated per build, never shipped.
#
#   tools/gen-keys.sh [output-dir]      (default: build/keys)
#
# For each role it writes <role>.crt (self-signed cert), <role>.crt.key (private
# key), <role>.cer (DER copy) and <role>.guid, which tools/build.sh consumes.
set -euo pipefail

OUT="${1:-build/keys}"
mkdir -p "$OUT"

for name in PK KEK db; do
    # Self-signed RSA-4096; swap for EC P-256 by using:
    #   -newkey ec -pkeyopt ec_paramgen_curve:P-256
    openssl req -newkey rsa:4096 -nodes \
        -keyout "$OUT/$name.crt.key" -new -x509 -sha256 -days 3650 \
        -subj "/CN=Lock.Boot/" -out "$OUT/$name.crt"
    openssl x509 -outform DER -in "$OUT/$name.crt" -out "$OUT/$name.cer"
    # Signature owner GUID: the fixed one GCP stamps on every X.509 cert it wraps into an
    # EFI_SIGNATURE_LIST for PK/KEK/db (undocumented; seen in GCE event logs 2022-2026). Using
    # it here makes our efi-vars.* ESLs byte-identical to what GCP enrolls from the .cer files,
    # so PCR7 is one value on QEMU, EC2 and GCP. Metadata only: never used for verification.
    echo d281fad2-8d88-47a4-9792-5baa47bb1b89 > "$OUT/$name.guid"
done

echo "Secure Boot keys written to $OUT (PK, KEK, db)"
