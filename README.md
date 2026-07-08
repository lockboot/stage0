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
      "x86_64": {
         "url": "http://cdn.example.com/app.efi",
         "sha256": "<64-hex sha256>"
      },
      "aarch64": {
         "ed25519": "<base64 pubkey>",
         "manifest_url": "http://cdn.example.com/app.manifest.json"
      }
   }
}
```

Per arch, pick the admission mode:

- **`sha256`**: pin an exact hash inline (`url` + `sha256`). Immutable; re-pin for every build.
- **`ed25519`**: pin a long-term release public key **and** a `manifest_url`. stage0 fetches a
  **signed manifest** from that URL (`{ "url", "sha256", "args", "version" }`), verifies its
  detached signature against the pinned key, then admits the payload by the manifest's exact
  `sha256`. Because the payload and its args are bound under **one** signature, a hostile mirror
  can neither mix-and-match independently-signed pieces nor roll the payload back to an old signed
  build -- yet you still roll forward by re-signing a new manifest (the user-data is unchanged).
  The signature is served at `<manifest_url>.sig`, or a `manifest_sig_url` of your choice (a
  `{sha256}` there is replaced with the *manifest's* hash, for content-addressing).

The payload must be a UEFI PE. However the firmware `db` feels about it, stage0
admits it by your pin/signature and measures it into **PCR 14** (= its SHA-256).

## `_stage1` metadata reference

A `_stage1` object with an optional inline `args` and one entry per architecture. Each arch
entry uses **exactly one** of `sha256` (static) or `ed25519` (signed manifest).

| Field | In | Type | Rules |
|---|---|---|---|
| `args` | `_stage1` | `string[]` | optional inline LoadOptions (sha256 mode; ed25519 mode uses the manifest's `args`) |
| `x86_64` / `aarch64` | `_stage1` | object | per-arch entry; the running arch's must be present |
| `url` | arch entry | `string`/list | **sha256 mode**: payload location(s), `http://…` printable ASCII (TLS not used) |
| `sha256` | arch entry | `string` | **sha256 mode**: exactly 64 hex characters |
| `ed25519` | arch entry | `string` | **ed25519 mode**: base64 of a 32-byte release public key |
| `manifest_url` | arch entry | `string`/list | **ed25519 mode**: where the signed manifest is fetched |
| `manifest_sig_url` | arch entry | `string`/list | optional; manifest signature location, `{sha256}` → *manifest* hash. Defaults to `<manifest_url>.sig` |

The **manifest** (ed25519 mode) is fetched from `manifest_url` and verified against `ed25519`:

| Field | Type | Rules |
|---|---|---|
| `url` | `string`/list | payload location(s); a `{sha256}` is replaced with the `sha256` below |
| `sha256` | `string` | the payload's exact 64 hex digest |
| `args` | `string[]` | optional; passed to the payload as LoadOptions |
| `version` | number | optional monotonic release version (anti-rollback hint; not yet enforced) |

Every URL field takes a single string or a fallback list (mirror resiliency); the content is
cryptographically pinned, so any mirror that verifies is accepted.

**Args model.** `args` (inline, sha256 mode) or the signed manifest's `args` (ed25519 mode) set
the booted EFI program's UEFI **LoadOptions** — the generic way stage0 parameterizes whatever EFI
image it chain-loads. They come **only** from this metadata (or the signed manifest); stage0 never
forwards its own firmware/shell invocation arguments to stage1. For a **Linux UKI** stage1, the
kernel command line is baked into the signed, measured UKI and is authoritative: under Secure Boot
the systemd stub **ignores** LoadOptions, so these cannot alter the UKI cmdline (and a replace
would also escape PCR 14). Production runs Secure Boot on; configure a UKI-based stage1 through its
`_stage2` document, not the kernel cmdline. A non-UKI EFI stage1 may read these LoadOptions as its
arguments.

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
