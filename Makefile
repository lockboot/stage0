# stage0 - measured UEFI network bootloader. Standalone build + test.
#
#   make / make build  build the db-signed boot.disk (host arch)
#   make boot          build + boot it under QEMU (signed test payload)
#   make test          alias for boot
# Append an arch suffix to target a specific one: build-x86_64, boot-aarch64, ...
# (default arch is `uname -m`). Knobs for boot:
#   PAYLOAD=<file>   serve a custom payload (sha256, or ed25519 if <file>.sig exists)
#   USER_DATA=<doc>  serve your own _stage1 doc verbatim
#   TRACE=1          capture the guest TCP stream to ./stage0-trace.pcap

.PRECIOUS: build/keys/% \
	build/%/stage0.efi build/%/payload.efi build/%/boot.disk

STAGE0_DIR = crates/stage0

# Default to the host architecture (uname -m gives x86_64 / aarch64 on Linux), so
# bare `make`, `make boot`, `make test` "just work". Override with ARCH=... or by
# using an explicit arch suffix, e.g. `make build-aarch64`.
ARCH ?= $(shell uname -m)
.DEFAULT_GOAL := build

# ---- Docker images (shared lockboot family; built locally, never published) ----
BUILD_IMAGE   = lockboot:build
HARNESS_IMAGE = lockboot:harness

.PHONY: docker-build-base docker-build-harness
docker-build-base:
	docker build -f Dockerfile.build -t $(BUILD_IMAGE) .

docker-build-harness:
	docker build -f Dockerfile.harness -t $(HARNESS_IMAGE) .

# ---- Docker run plumbing ----
# Own build artifacts by whoever owns the checkout, not the caller's euid. Under
# `gh act` the caller is root but the bind-mounted tree is still yours, so stat
# keeps output user-owned instead of trampling the project dir with root files.
# On a normal host/devcontainer run this equals `id -u`/`id -g`, so nothing changes.
USER_ID  := $(shell stat -c %u .)
GROUP_ID := $(shell stat -c %g .)

KVM_GID   := $(shell stat -c %g /dev/kvm 2>/dev/null || echo "")
KVM_MOUNT := $(shell test -e /dev/kvm && echo "-v /dev/kvm:/dev/kvm")
DOCKER_OPT_KVM := $(if $(KVM_GID),--group-add $(KVM_GID)) $(KVM_MOUNT)

DOCKER_SAMEUSER := -u $(USER_ID):$(GROUP_ID)

# Host-path translation for docker-in-devcontainer. Inside the devcontainer /src is
# a host bind mount and the inner Docker talks to the HOST daemon, which cannot
# resolve /src/... paths; translate $(CURDIR) to the real host path (the bracketed
# subpath findmnt reports for the /src bind). On the host CURDIR is not under /src,
# so this is a pass-through and your workflow is unchanged. Keep identical across repos.
HOST_DIR := $(CURDIR)
ifneq ($(filter /src/%,$(CURDIR)),)
  SRC_BIND := $(shell findmnt -fnro SOURCE --target /src 2>/dev/null | sed -n 's/.*\[\(.*\)\]$$/\1/p')
  ifneq ($(SRC_BIND),)
    HOST_DIR := $(SRC_BIND)$(CURDIR:/src%=%)
  endif
endif

# Mount the WORKSPACE (parent of this repo) at /src so builds reuse the shared
# workspace-level .cargo/.rustup (matching the devcontainer), instead of creating
# per-repo copies. The repo then lives at /src/$(REPO_NAME).
REPO_NAME := $(notdir $(HOST_DIR))
HOST_WS   := $(patsubst %/,%,$(dir $(HOST_DIR)))

# Under CI / `gh act` (CI=true, runs as root) keep cargo/rustup caches ephemeral
# inside the container, so root-owned dirs never land in the bind-mounted project.
# Locally (no CI) the image's CARGO_HOME=/src/.cargo + RUSTUP_HOME=/src/.rustup win,
# i.e. the shared workspace caches.
CACHE_ENV := $(if $(CI),-e CARGO_HOME=/tmp/.cargo -e RUSTUP_HOME=/tmp/.rustup)

DOCKER_RUN = docker run --rm \
	--privileged \
	-v $(HOST_WS):/src \
	-h lockboot \
	--add-host lockboot:127.0.0.1 \
	-e OWNER_UID=$(USER_ID) \
	-e OWNER_GID=$(GROUP_ID) \
	$(CACHE_ENV) \
	-w /src/$(REPO_NAME)

# ---- Secure Boot keys: stage0's own snakeoil PK/KEK/db (regenerated per build) ----
# The pattern rule generates the whole set into build/keys via tools/gen-keys.sh;
# release.pem (below) is matched by its explicit rule instead.
build/keys/%: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) ./tools/gen-keys.sh build/keys

# ---- ed25519 release key for "signed mode" payload admission ----
# Vendor key; stage0 only ever sees the public half, pinned in the metadata doc.
build/keys/release.pem: docker-build-base
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/keys && \
		openssl genpkey -algorithm ed25519 -out build/keys/release.pem && \
		openssl pkey -in build/keys/release.pem -pubout -outform DER \
			| tail -c 32 | base64 -w0 > build/keys/release.pub.b64"

# ---- Build the stage0 UEFI binary ----
# mkdir runs inside the container (as DOCKER_SAMEUSER) so the output dir is owned
# by the build user, not by the host caller (which is root under `gh act`).
build/%/stage0.efi: docker-build-base
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "mkdir -p build/$* && rustup target add $*-unknown-uefi && cargo build --release --manifest-path $(STAGE0_DIR)/Cargo.toml --target $*-unknown-uefi && cp -v $(STAGE0_DIR)/target/$*-unknown-uefi/release/stage0.efi $@"

# ---- Assemble + db-sign the boot disk (privileged: losetup/mount) ----
build/%/boot.disk: build/%/stage0.efi build/keys/db.crt
	$(DOCKER_RUN) -e ARCH=$* $(BUILD_IMAGE) ./tools/build.sh

build-amd64 build-x86_64:  build/x86_64/boot.disk
build-arm64 build-aarch64: build/aarch64/boot.disk

# ---- Test payload: a chain-loaded UEFI app that reads PCRs, ed25519-signed ----
# Served at a hostname (not an IP) so the test also exercises EFI_DNS4; qemu-test.sh
# maps payload.lockboot.test -> 10.0.2.1. Override SERVE_HOST=10.0.2.1:8000 to skip DNS.
SERVE_HOST ?= payload.lockboot.test:8000
PAYLOAD_URL ?= http://$(SERVE_HOST)/payload.efi
build/%/payload.efi: docker-build-base build/keys/release.pem
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "mkdir -p build/$* && rustup target add $*-unknown-uefi && cargo build --release --manifest-path crates/stage0-test-payload/Cargo.toml --target $*-unknown-uefi && \
			cp crates/stage0-test-payload/target/$*-unknown-uefi/release/stage0-test-payload.efi $@ && \
			openssl pkeyutl -sign -inkey build/keys/release.pem -rawin -in $@ -out $@.sig"

# ---- QEMU harness: the lean harness image bakes qemu-test.sh as its entrypoint
# (and the EC2_MOCK_CACHE + iptables-ack env), so we just append CLI args. ----
STAGE0_QEMU = $(DOCKER_RUN) $(DOCKER_OPT_KVM) \
	--cap-add=NET_ADMIN --device=/dev/net/tun \
	$(HARNESS_IMAGE)

# Boot stage0 under QEMU. Defaults to the signed test payload and regenerates the
# user-data each run so it can never go stale.
boot-%: build/%/boot.disk build/%/payload.efi docker-build-harness
	@P="$(PAYLOAD)"; [ -n "$$P" ] || P="build/$*/payload.efi"; \
	if [ -n "$(USER_DATA)" ]; then \
		cp "$(USER_DATA)" user-data.stage0.json; \
		echo "Using user-data from $(USER_DATA)"; \
	elif [ -f "$$P.sig" ] && [ -f build/keys/release.pub.b64 ]; then \
		PUB=$$(cat build/keys/release.pub.b64); \
		printf '{\n  "_stage1": {\n    "%s": { "url": "%s", "ed25519": "%s" }\n  }\n}\n' \
			"$*" "$(PAYLOAD_URL)" "$$PUB" > user-data.stage0.json; \
		echo "Wrote user-data.stage0.json (signed mode, release pubkey $$PUB)"; \
	else \
		SHA=$$(sha256sum "$$P" | cut -d' ' -f1); \
		printf '{\n  "_stage1": {\n    "%s": { "url": "%s", "sha256": "%s" }\n  }\n}\n' \
			"$*" "$(PAYLOAD_URL)" "$$SHA" > user-data.stage0.json; \
		echo "Wrote user-data.stage0.json (sha256 mode, $$SHA)"; \
	fi; \
	$(STAGE0_QEMU) --kind stage0 --arch $* \
		--boot-disk build/$*/boot.disk \
		--user-data user-data.stage0.json --payload "$$P" $(if $(TRACE),--trace)

test-%:
	$(MAKE) boot-$* TRACE=$(TRACE)

# Arch-less convenience forms target the host architecture ($(ARCH)).
.PHONY: build boot test
build: build-$(ARCH)
boot:  boot-$(ARCH)
test:  test-$(ARCH)

.PHONY: clean
# Remove per-arch build output and the cargo target/ trees in each crate workspace.
# Plain rm (not `cargo clean`) so it needs no docker image and works on a checkout
# that was never built. build/keys/ (snakeoil + release key) is left in place.
clean:
	rm -rf build/x86_64 build/aarch64 crates/*/target
