# Publishing stage0 cloud images

Turn a built stage0 boot disk into a bootable cloud image (AWS AMI or GCP image).
The image boots stage0, which then fetches your payload over HTTP per the `_stage1`
user-data document (see the top-level README). These scripts run on your **host**
and use your cloud credentials; they are not part of the build container.

The image is generic: nothing in it is per-customer, so one image per `(release,
arch)` serves everyone. The per-deployment config lives in the `_stage1` user-data
you pass at launch, not in the image.

## What it consumes

Each publisher reads the per-arch build output:

| File | Used by | Purpose |
|---|---|---|
| `build/<arch>/boot.disk` | both | raw GPT/UEFI disk that boots stage0 |
| `build/<arch>/efi-vars.aws` | EC2 | AWS-format Secure Boot variable store (`--uefi-data`) |
| `build/<arch>/os-release` | both | names/tags the image (`ID`, `VERSION_ID`, `BUILD_ID`) |
| `build/<arch>/{PK,KEK,db}.cer` | GCP | custom Secure Boot keys |

Produce them with `make build-<arch>`. Or pass a `stage0-v*` release tag as the
`version` argument (instead of the default `local`) to download and
attestation-verify the published release artifacts.

## Host dependencies

- **EC2**: `aws` (authenticated), `coldsnap` (`cargo install --locked coldsnap`) —
  writes the raw boot disk straight to an EBS snapshot via the EBS Direct API
  (needs `ebs:StartSnapshot`/`PutSnapshotBlock`/`CompleteSnapshot`), no S3/role
- **GCP**: `gcloud` (`gcp/install-gcloud.sh` installs it locally if you lack it)
- **Release mode** (`version` is a tag): `gh` + `unzip`, or pass `--no-verify` to
  fetch the public release asset with `curl` instead (skips attestation, no `gh`)

## Common interface

Each provider has a `create.sh` under its own directory. They share the same shape
and default to a nearby region and a **public** image:

```
ec2/create.sh  [--region R]               [--public|--private] [--no-verify] [--manifest F] <arch> [version]
```

```
gcp/create.sh  [--project P] [--region R] [--public|--private] [--no-verify] [--manifest F] <arch> [version]
```

- `<arch>` is `x86_64` or `aarch64`; `version` is `local` (default) or a `stage0-v*` tag.
- `--region` default: `ap-southeast-1` (AWS, Singapore) / `asia-southeast1`
  (GCP, Singapore). Singapore is the always-on default; KL `ap-southeast-5` works
  but is an opt-in region you must enable on the account first.
- `--project` (GCP) default: the active `gcloud` project.
- `--public` (default) makes the image launchable by anyone; `--private` keeps it to your account/project.
- `--no-verify` skips attestation and fetches via `curl` (release mode, public repos).
- `--manifest F` appends every created resource to `F` for teardown (see Cleanup).
- Each script prints **only the created ID** (AMI ID / image name) to stdout; all
  progress goes to stderr, so you can capture it: `AMI=$(ec2/create.sh x86_64)`.
- `-h`/`--help` on any script prints full usage.

Both are **idempotent**: re-running reuses an existing snapshot/AMI/image (matched by
the build's `BUILD_ID`) instead of recreating it. Safe to Ctrl-C and re-run.

## EC2 (AMI)

```bash
# Build (or download) the disk and register a public UEFI/TPM-v2 AMI in Singapore.
AMI=$(tools/publish/ec2/create.sh x86_64)

# Launch it with your _stage1 user-data and stream the serial console until it
# powers off. Instance type is derived from the AMI architecture; --spot for spot.
tools/publish/ec2/launch.sh --tail "$AMI" config.json
```

`launch.sh <ami-id> <config-file>` takes the same `--region` default as `create.sh`,
auto-picks the instance type from the AMI architecture (`c6i.large` x86_64 /
`c7g.medium` arm64, override with `--instance-type`), and supports `--spot`. `--tail`
streams the serial console until the instance powers off, then keeps draining for ~2
min because EC2's serial buffer lags. The launched instance ID is printed to stdout.

Shutdown behavior defaults to **terminate** — these are ephemeral test boxes that
self-destruct when stage0 powers off. Pass **`--stop`** to keep the instance instead,
so it (and its serial console log) survive for debugging a fast-failing boot; clean it
up afterward with `aws ec2 terminate-instances …`. Caveat: a one-time **`--spot`**
instance cannot stop, so `--stop` is ignored under `--spot` and the log is lost — omit
`--spot` when you need `--stop`.

`create.sh` snapshots the raw `boot.disk` straight to EBS with **coldsnap** (the EBS
Direct API) — seconds, not the minutes VM Import took, and with no S3 bucket, no VMDK
conversion, and no `vmimport` role. It just needs `ebs:StartSnapshot`,
`ebs:PutSnapshotBlock`, and `ebs:CompleteSnapshot` on your identity. Re-runs reuse an
existing snapshot tagged with the build's `BUILD_ID`.

Registers with `--boot-mode uefi`, `--tpm-support v2.0`, `--imds-support v2.0`, and
the Secure Boot vars from `efi-vars.aws`. If your account has the default "block
public access for AMIs" enabled, the public step prints the
`aws ec2 disable-image-block-public-access` command to run.

## GCP (Confidential VM image)

```bash
tools/publish/gcp/install-gcloud.sh                 # if you don't already have gcloud

IMG=$(tools/publish/gcp/create.sh x86_64)           # active project, public, Singapore
tools/publish/gcp/launch-instance.sh my-vm asia-southeast1-a n2d-standard-2 "$IMG" config.json
tools/publish/gcp/get-console.sh my-vm asia-southeast1-a --follow
```

Uploads `boot.disk` as a `disk.raw` tarball to GCS and creates a global image with
your custom PK/KEK/db and these guest-OS features (idempotent: an existing GCS upload
is reused):

- `UEFI_COMPATIBLE` — required for UEFI boot.
- `SEV_CAPABLE`, `SEV_SNP_CAPABLE` — x86_64 only; mark the image launchable as an AMD
  SEV / SEV-SNP Confidential VM.
- `GVNIC` — Google Virtual NIC.
- aarch64 gets `UEFI_COMPATIBLE` + `GVNIC` only (ARM confidential compute needs no
  guest-OS feature flag).

We create the image directly from GCS rather than `gcloud compute images import`
because `import` demands a predefined `--os` (e.g. `ubuntu-2204`) and won't set custom
guest-OS features — stage0 is kernel-less, so there is no OS for it to detect.

**Trust-model requirement:** Confidential VMs must run with
`--maintenance-policy=TERMINATE` (no live migration — migration would expose decrypted
guest memory to the hypervisor). Never enable the `SEV_LIVE_MIGRATABLE` feature.
`launch-instance.sh` bakes this in along with `--confidential-compute`,
`--shielded-secure-boot`, `--shielded-vtpm`, and `--shielded-integrity-monitoring`.

Confidential VM machine types: `n2d-standard-*` (SEV / SEV-SNP), `c2d-standard-*`
(SEV-SNP, compute-optimized), `c3-standard-*` (Intel TDX), `t2a-standard-*` (ARM64).

How GCP differs from EC2 here: GCP manages the Secure Boot vars and vTPM itself (no
`--uefi-data` / `--tpm-support`), memory is encrypted by SEV/SEV-SNP/TDX, and the
`_stage1` user-data is **required** (passed as `--metadata-from-file=user-data=`),
whereas EC2 takes it via `--user-data` and treats it as optional.

## Cleanup (teardown while testing)

Pass `--manifest <file>` to the create scripts to record what they make, then feed
it to `cleanup.sh`. Lines are `<provider> <kind> <region-or-project> <id-or-uri>`;
the file accumulates across runs, so one file can capture both arches and both clouds.

```bash
tools/publish/cleanup.sh --dry-run teardown.txt   # preview the delete commands
tools/publish/cleanup.sh teardown.txt             # tear it all down
```

`cleanup.sh` processes the manifest bottom-to-top (so AMIs deregister before their
snapshots), treats already-gone resources as warnings (safe to re-run), and skips
lines whose CLI isn't installed.

## End-to-end (test loop)

```bash
make build-x86_64
AMI=$(tools/publish/ec2/create.sh --manifest teardown.txt x86_64)
IMG=$(tools/publish/gcp/create.sh --manifest teardown.txt x86_64)
# launch on each cloud with your _stage1 user-data, capture the serial console / PCRs
tools/publish/cleanup.sh teardown.txt
```

## Azure

Not implemented yet (placeholder dir). stage0 already speaks the Azure IMDS at boot;
only the image-publishing script is missing.
