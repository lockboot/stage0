# stage0

**Authenticated HTTP UEFI Secure NetBoot for the Cloud**

stage0 boots a cloud VM, it uses EC2, GCP, Azure or Alibaba Cloud JSON metadata
JSON you provide to fetch a UEFI payload (typically a Linux UKI) over HTTP, then
verifies it with the pinned hash or ed25519 signature, measures it into TPM PCR 14,
and chain-loads it.

Basically it's netboot without PXE: no TFTP, no DHCP options, no in-guest agent.
Update the served payload and VMs roll forward on reboot;
read the TPM and you know precisely which binary is running.
All authenticated from your product updates URL and release keys.

## Using it

stage0 ships as a `db`-signed boot disk; use it as your VM's boot volume. Point
it at your payload with a `_stage1` user-data document:

```json
{
   "_stage1": {
      "x86_64":  { "payload": { "url": "http://cdn.example.com/app.efi", "sha256": "<64-hex sha256>" } },
      "aarch64": { "payload": {
         "url": "http://cdn.example.com/app.efi",
         "ed25519": "<base64 pubkey>",
         "args_url": "http://cdn.example.com/app.args"
      } }
   }
}
```

Each arch entry is a discriminated union — exactly one of a `payload` (admit a
binary now) or a `manifest` (resolve a signed manifest first):

- **`payload` / `sha256`**: pin an exact hash. Immutable; re-pin for every build.
- **`payload` / `ed25519`**: pin a long-term release public key. The payload rolls
  forward without editing metadata: sign each build offline and serve the detached
  signature at `<url>.sig`, or at a `sig_url` of your choice. A `{sha256}` in
  `sig_url` is replaced with the payload's hash, so signatures can be
  content-addressed (e.g. `http://cdn.example.com/sigs/{sha256}.sig`).
- **`manifest`**: pin a release key **and** a manifest URL. stage0 fetches the signed
  manifest (a `_stage1` fragment), verifies its detached signature (`<url>.sig`, or
  `sig_url`) against the pinned `ed25519` key, deep-merges it, and re-evaluates —
  looping through a chain of signed manifests (per-hop key delegation) until it
  reaches a payload; a repeated `(url, sha256)` is a cycle and fails closed. Binding
  the payload + args under one manifest signature stops mix-and-match of independently
  signed pieces. Optional `manifest.sha256` also pins the manifest's own bytes.

  ```json
  { "_stage1": { "x86_64": { "manifest": { "url": "http://cdn.example.com/app.manifest.json", "ed25519": "<base64 pubkey>" } } } }
  ```

The payload must be a UEFI PE. However the firmware `db` feels about it, stage0
admits it by your pin/signature and measures it into **PCR 14** (= its SHA-256).

## Testing

`make boot` builds the `db`-signed boot disk and boots it under QEMU, serving a small test
payload that reads the PCRs and prints them. Pick a mode with `SIGN=1` (ed25519), `SIGN_ARGS=1`
(signed LoadOptions), `MANIFEST=1` (resolve a signed `_stage1` manifest), `FALLBACK=1` (mirror
fallback), or `ARGS='[…]'` (inline LoadOptions).

`make smoke-boot` runs the whole matrix as an **asserting** suite — each admission mode boots
`stage0 → test-payload` and verifies the payload actually chain-loaded (proving fetch → admit →
PCR-measure → chain-load), printing a per-mode PASS/FAIL summary. It needs nested KVM (local only)
and takes ~2 minutes. Everything is regenerated and signed reproducibly from the Makefile — no
manual steps.

Under the test harness the payload runs with `--nosleep` in its LoadOptions (skipping its
EC2-only ~60s serial-flush hold, which QEMU doesn't need) and powers the machine off at the end
instead of returning to stage0 — so each boot exits promptly. A real EC2 deploy passes no such
flag and keeps the full drain; nothing is gated behind a separate build.

## `_stage1` metadata reference

A `_stage1` object with one entry per architecture; the running arch's must be present.
Each arch entry is `{ "payload": {…} }` (needs `url` **and exactly one** of `sha256` /
`ed25519`) or `{ "manifest": {…} }` (needs `url` + `ed25519`).

| Field | In | Type | Rules |
|---|---|---|---|
| `x86_64` / `aarch64` | `_stage1` | object | per-arch union entry; the running arch's must be present |
| `url` | payload / manifest | `string`/list | `http://…`, printable ASCII (TLS is not used) |
| `sha256` | payload | `string` | exactly 64 hex characters |
| `ed25519` | payload / manifest | `string` | base64 of a 32-byte public key |
| `sig_url` | payload / manifest | `string`/list | optional (signed mode); signature location, `{sha256}` → payload/manifest hash. Defaults to `<url>.sig` |
| `args` | payload | `string[]` | optional inline UEFI load options |
| `args_url` | payload | `string`/list | optional (signed mode only); fetch signed load options here, `{sha256}` → payload hash. Overrides inline `args` |
| `args_sig_url` | payload | `string`/list | optional; signature for `args_url`, `{sha256}` → payload hash. Defaults to `<args_url>.sig`. Requires `args_url` |
| `sha256` | manifest | `string` | optional; pins the manifest's own bytes (64 hex) |

`args_url` content is verified against `ed25519` (the same release key as the
payload) and used verbatim, trimmed, as the load-options string.

**Args model.** `args` / `args_url` set the booted EFI program's UEFI **LoadOptions** —
the generic way stage0 parameterizes whatever EFI image it chain-loads. They come **only**
from this metadata (or the signed URL); stage0 never forwards its own firmware/shell
invocation arguments to stage1. For a **Linux UKI** stage1, the kernel command line is
baked into the signed, measured UKI and is authoritative: under Secure Boot the systemd
stub **ignores** LoadOptions, so `args` cannot alter the UKI cmdline (and a replace would
also escape PCR 14). Production runs Secure Boot on; configure a UKI-based stage1 through
its `_stage2` document, not the kernel cmdline. A non-UKI EFI stage1 may read these
LoadOptions as its arguments.

### Embedded metadata (self-contained `netboot.efi`)

The `_stage1` document can be embedded in stage0's PE before Authenticode
signing. If a `.stage0` section is present, stage0 reads the document from that
section and does not contact the metadata service. The metadata is either embedded
or fetched, never both.

The section holds the complete user-data JSON: the same `{ "_stage1": { ... } }`
document the metadata service would return, not just the inner object. It is part
of the signed, firmware-measured image, so the key, URL and args it pins are fixed
at signing time. The result is a single file that runs one fixed configuration,
with the payload still gated by your release key.

Embed the document, then sign:

    objcopy --add-section .stage0=user-data.json \
            --set-section-flags .stage0=alloc,load,readonly,data \
            stage0.efi netboot.efi
    sbsign --key db.key --cert db.crt --output netboot.efi netboot.efi

The section must be loaded: mapped at its virtual address, with `SizeOfImage`
covering it. If it is not, stage0 ignores it and falls back to the metadata
service.

## What it does

On boot, in order:

1. Brings the NIC up via DHCP (`EFI_IP4_CONFIG2`).
2. Fetches `_stage1` user-data from the metadata service, trying
   EC2 IMDSv2, GCP, Azure & Alibaba Cloud at their fixed IPs.
3. Downloads the per-arch payload from `url` (hostnames resolved via `EFI_DNS4`).
   All networking is raw `EFI_TCP4`, no `EFI_HTTP` or TLS; integrity comes from
   the pin/signature, not the transport.
4. **Admits** it: its SHA-256 must equal the pinned `sha256`, or a detached
   ed25519 signature (`<url>.sig`) must verify against the pinned `ed25519` key.
5. **Measures** it: `PCR 14 ← SHA-256(payload)` via `EFI_TCG2_PROTOCOL`. Nothing
   else is measured; attestation is simply "stage0 ran and loaded this hash"
   (no config, key, or PCR 15).
6. **Chain-loads** it (`LoadImage` from memory + `StartImage`), bypassing the
   firmware `db` check with a temporary `FileAuthentication` override so
   late-bound payloads need no `db` signature.

stage0 is itself `db`-signed and measured, so the chain stays attestable; the
pin/signature is admission control only and is never attested.
