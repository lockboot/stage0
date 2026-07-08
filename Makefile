# stage0 - measured UEFI network bootloader. Standalone build + test.
#
#   make / make build  build the db-signed boot.disk (host arch)
#   make boot          build + boot it under QEMU (sha256 mode by default)
#   make test          alias for boot
#   make smoke-boot    asserting boot-test matrix: every admission mode (sha256, ed25519,
#                      signed-args, signed manifest, mirror fallback), each verified to
#                      chain-load the payload. Local-only (nested KVM), several minutes.
# Append an arch suffix to target a specific one: build-x86_64, boot-aarch64, smoke-boot-aarch64...
# (default arch is `uname -m`). Boot modes (SIGN=1 / SIGN_ARGS=1 / MANIFEST=1 / FALLBACK=1 /
# ARGS='[..]' / PAYLOAD=<file> / USER_DATA=<doc>) are documented at the boot-% rule below.
#   TRACE=1            capture the guest TCP stream to ./stage0-trace.pcap

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

# ---- Build the ena.efi UEFI driver (embedded into stage0 for EC2/ENA netboot) ----
# A resident SimpleNetworkProtocol driver for the AWS ENA NIC, which Nitro's UEFI
# firmware does not provide. stage0 include_bytes! build/$*/ena.efi unconditionally.
# Mark precious: it is only a prerequisite of the stage0.efi pattern rule, so make
# would otherwise treat it as a chained intermediate and delete it after the build.
.PRECIOUS: build/%/ena.efi
build/%/ena.efi: docker-build-base
	$(DOCKER_RUN) -e ARCH=$* $(DOCKER_SAMEUSER) $(BUILD_IMAGE) \
		bash -c "mkdir -p build/$* && rustup target add $*-unknown-uefi && cargo build --release --manifest-path crates/ena/Cargo.toml --target $*-unknown-uefi && cp -v crates/ena/target/$*-unknown-uefi/release/ena.efi $@"

# ---- Build the stage0 UEFI binary ----
# mkdir runs inside the container (as DOCKER_SAMEUSER) so the output dir is owned
# by the build user, not by the host caller (which is root under `gh act`).
# stage0 include_bytes! build/$*/ena.efi unconditionally (one measured unit), so the
# ena.efi prerequisite must be built first; nothing extra to pass on the command line.
build/%/stage0.efi: build/%/ena.efi docker-build-base
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

# ---- Signed remote LoadOptions for SIGN_ARGS=1: a JSON array of strings, ed25519-signed like
# the payload. stage0 fetches args.json + args.json.sig, verifies against the pinned key, and
# uses them as the child's UEFI LoadOptions (overriding inline args). ----
build/%/args.json.sig: build/keys/release.pem
	$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c "\
		mkdir -p build/$* && \
		printf '%s' '[\"--from\",\"signed-args\",\"--nosleep\"]' > build/$*/args.json && \
		openssl pkeyutl -sign -inkey build/keys/release.pem -rawin \
			-in build/$*/args.json -out build/$*/args.json.sig"

# ---- QEMU harness: the lean harness image bakes qemu-test.sh as its entrypoint
# (and the EC2_MOCK_CACHE + iptables-ack env), so we just append CLI args. ----
STAGE0_QEMU = $(DOCKER_RUN) $(DOCKER_OPT_KVM) \
	--cap-add=NET_ADMIN --device=/dev/net/tun \
	$(HARNESS_IMAGE)

# Boot stage0 under QEMU. Serves a staging dir (so payload, signed args, and a signed
# manifest are all served uniformly at http://SERVE_HOST/<file>) and regenerates the
# user-data each run so it can never go stale. Each arch entry is the `{ "payload" | "manifest" }`
# discriminated union. Modes:
#   (default)    sha256 pin of the payload.
#   SIGN=1       ed25519 detached-sig admission (serves payload.efi.sig).
#   SIGN_ARGS=1  (implies signed) signed LoadOptions via args_url (serves args.json + .sig).
#   MANIFEST=1   (implies signed) resolve a signed `_stage1` manifest that pins the payload,
#                exercising stage0's manifest-resolution loop + top-level merge.
#   FALLBACK=1   payload/manifest url is a list [dead 10.0.2.1:9, real] (mirror fallback).
#   ARGS='[..]'  inline payload LoadOptions, verbatim (ignored under SIGN_ARGS). With no ARGS,
#                make passes `--nosleep` so the payload skips its EC2-only ~60s serial-flush hold;
#                the payload also powers off at the end rather than returning to stage0 (which
#                would trigger stage0's own ~90s fail-closed drain) -- so QEMU exits promptly.
#   PAYLOAD=<f>  serve a custom payload instead of the built test payload.
#   USER_DATA=<doc>  serve the payload dir but boot your own `_stage1` doc verbatim.
boot-%: build/%/boot.disk build/%/payload.efi docker-build-harness \
		$(if $(SIGN_ARGS),build/%/args.json.sig)
	@D="build/$*/serve"; rm -rf "$$D"; mkdir -p "$$D"; H="http://$(SERVE_HOST)"; \
	P="$(PAYLOAD)"; [ -n "$$P" ] || P="build/$*/payload.efi"; \
	cp "$$P" "$$D/payload.efi"; \
	URLVAL="\"$$H/payload.efi\""; \
	if [ -n "$(FALLBACK)" ]; then URLVAL="[ \"http://10.0.2.1:9/payload.efi\", \"$$H/payload.efi\" ]"; echo "fallback: url = [dead 10.0.2.1:9, $$H/payload.efi]"; fi; \
	INLINE_ARGS=""; \
	if [ -z "$(SIGN_ARGS)" ]; then \
		if [ -n '$(ARGS)' ]; then INLINE_ARGS=", \"args\": $$(printf '%s' '$(ARGS)')"; echo "LoadOptions = $(ARGS)"; \
		else INLINE_ARGS=", \"args\": [\"--nosleep\"]"; fi; \
	fi; \
	if [ -n "$(USER_DATA)" ]; then \
		cp "$(USER_DATA)" user-data.stage0.json; echo "using user-data from $(USER_DATA)"; \
	elif [ -n "$(SIGN)$(SIGN_ARGS)$(MANIFEST)" ]; then \
		PUB=$$(cat build/keys/release.pub.b64); \
		if [ -n "$(MANIFEST)" ]; then \
			SHA=$$(sha256sum "$$D/payload.efi" | cut -d' ' -f1); \
			printf '{ "_stage1": { "%s": { "payload": { "url": %s, "sha256": "%s"%s } } } }\n' "$*" "$$URLVAL" "$$SHA" "$$INLINE_ARGS" > "$$D/stage1.manifest.json"; \
			$(DOCKER_RUN) $(DOCKER_SAMEUSER) $(BUILD_IMAGE) bash -c \
				"openssl pkeyutl -sign -inkey build/keys/release.pem -rawin -in $$D/stage1.manifest.json -out $$D/stage1.manifest.json.sig"; \
			printf '{\n  "_stage1": { "%s": { "manifest": { "url": "%s/stage1.manifest.json", "ed25519": "%s" } } }\n}\n' "$*" "$$H" "$$PUB" > user-data.stage0.json; \
			echo "user-data: _stage1 via signed manifest (pubkey $$PUB)"; \
		else \
			cp "$$P.sig" "$$D/payload.efi.sig"; \
			PAY="\"url\": $$URLVAL, \"ed25519\": \"$$PUB\""; \
			if [ -n "$(SIGN_ARGS)" ]; then \
				cp build/$*/args.json "$$D/args.json"; cp build/$*/args.json.sig "$$D/args.json.sig"; \
				PAY="$$PAY, \"args_url\": \"$$H/args.json\""; \
			fi; \
			printf '{\n  "_stage1": { "%s": { "payload": { %s%s } } }\n}\n' "$*" "$$PAY" "$$INLINE_ARGS" > user-data.stage0.json; \
			echo "user-data: signed mode (pubkey $$PUB)"; \
		fi; \
	else \
		SHA=$$(sha256sum "$$D/payload.efi" | cut -d' ' -f1); \
		printf '{\n  "_stage1": { "%s": { "payload": { "url": %s, "sha256": "%s"%s } } }\n}\n' "$*" "$$URLVAL" "$$SHA" "$$INLINE_ARGS" > user-data.stage0.json; \
		echo "user-data: sha256 mode ($$SHA)"; \
	fi; \
	$(STAGE0_QEMU) --kind stage0 --arch $* \
		--boot-disk build/$*/boot.disk \
		--user-data user-data.stage0.json --serve-dir "$$D" $(if $(TRACE),--trace)

test-%:
	$(MAKE) boot-$* TRACE=$(TRACE)

# ---- Reproducible boot-test matrix: boot stage0 -> test-payload in every admission mode and
# assert the chain-loaded payload actually ran (its `payload: done` proves stage0 fetched,
# admitted, PCR-measured, and chain-loaded it). Local-only (nested KVM); each boot self-powers-off
# after the payload's serial-drain hold, so the whole matrix takes several minutes. ----
.PHONY: smoke-boot
smoke-boot-%: build/%/boot.disk build/%/payload.efi build/%/args.json.sig docker-build-harness
	@fail=0; sum="build/$*/smoke-boot.summary"; : > "$$sum"; \
	for m in "sha256:" "sign:SIGN=1" "sign_args:SIGN=1 SIGN_ARGS=1" "manifest:SIGN=1 MANIFEST=1" "fallback:FALLBACK=1"; do \
		name="$${m%%:*}"; vars="$${m#*:}"; log="build/$*/boot-$$name.log"; \
		echo "==================== stage0 boot test [$$name] $$vars ===================="; \
		echo "  booting (runs to self-poweroff so QEMU releases the boot.disk lock before the next mode) -> $$log"; \
		$(MAKE) --no-print-directory boot-$* $$vars > "$$log" 2>&1 || true; \
		if grep -q 'payload: done' "$$log"; then \
			echo "PASS [$$name]" | tee -a "$$sum"; \
		else \
			echo "FAIL [$$name] (see $$log)" | tee -a "$$sum"; fail=1; \
		fi; \
	done; \
	echo "==================== stage0 boot-test summary ===================="; cat "$$sum"; \
	if [ "$$fail" = 0 ]; then echo "ALL STAGE0 BOOT TESTS PASSED"; else echo "SOME STAGE0 BOOT TESTS FAILED"; exit 1; fi

smoke-boot: smoke-boot-$(ARCH)

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
