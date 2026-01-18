.PHONY: help run-help build run clean distclean install-lambda-test-tool local build-lambda package \
        clean-cert-cache clean-cert-cache-windows clean-cert-cache-macos \
        run-nocheck run-online-soft run-online-strict run-offline-soft run-offline-strict \
        run-base-nocheck run-base-online-soft run-base-online-strict

# -------------------------------------------------------------------
# Makefile (macOS/Linux + Windows for cert-cache clearing)
# -------------------------------------------------------------------
# This Makefile primarily targets macOS/Linux.
# It also includes a Windows-friendly target to clear the CryptoAPI URL cache
# (CRL/OCSP/cert retrieval cache) via certutil.

# -------------------------------------------------------------------
# Local runner defaults (override at runtime)
# -------------------------------------------------------------------
LOCAL_PROJ := ./src/Horacio-TLS-Lambda.Local/Horacio-TLS-Lambda.Local.csproj
LAMBDA_PROJ_DIR := ./src/Horacio-TLS-Lambda
LAMBDA_PROJ := ./src/Horacio-TLS-Lambda/Horacio-TLS-Lambda.csproj
CONFIG ?= Release

# Default URL if none is specified
URL ?= https://example.com

# Revocation mode and behavior
# REV_MODE: NoCheck | Online | Offline
# SOFTFAIL: true | false
REV_MODE ?= NoCheck
SOFTFAIL ?= true

# Optional certificate file paths (only used if your Program.cs supports them)
CA_ROOT_PEM_FILE ?=
INTERMEDIATE_PEM_FILE ?=

# Optional flags builder
CA_ARGS :=
ifneq ($(strip $(CA_ROOT_PEM_FILE)),)
  CA_ARGS += --caRootPemFile "$(CA_ROOT_PEM_FILE)"
endif
ifneq ($(strip $(INTERMEDIATE_PEM_FILE)),)
  CA_ARGS += --intermediatePemFile "$(INTERMEDIATE_PEM_FILE)"
endif

# -------------------------------------------------------------------
# Help
# -------------------------------------------------------------------
help: run-help

run-help:
	@echo "Horacio-TLS-Lambda Makefile help"
	@echo ""
	@echo "Common usage:"
	@echo "  make build"
	@echo "  make run"
	@echo "  make run URL=https://google.com"
	@echo "  make clean-cert-cache   (clear TLS revocation/cert URL caches; OS-aware)"
	@echo ""
	@echo "Revocation options:"
	@echo "  REV_MODE = NoCheck | Online | Offline"
	@echo "  SOFTFAIL = true | false"
	@echo ""
	@echo "Examples:"
	@echo "  make run URL=https://example.com REV_MODE=Online SOFTFAIL=true"
	@echo "  make run URL=https://example.com REV_MODE=Online SOFTFAIL=false"
	@echo ""
	@echo "Shortcuts:"
	@echo "  make run-nocheck"
	@echo "  make run-online-soft"
	@echo "  make run-online-strict"
	@echo "  make run-offline-soft"
	@echo "  make run-offline-strict"
	@echo ""
	@echo "Base URL shortcuts (edit URL_BASE inside the Makefile):"
	@echo "  make run-base-nocheck"
	@echo "  make run-base-online-soft"
	@echo "  make run-base-online-strict"
	@echo ""
	@echo "Private CA files (optional):"
	@echo "  make run URL=https://private.local CA_ROOT_PEM_FILE=./root.pem INTERMEDIATE_PEM_FILE=./intermediate.pem"
	@echo ""
	@echo "Certificate cache helpers:"
	@echo "  make clean-cert-cache"
	@echo "    - Windows: certutil -urlcache * delete (CRL/OCSP cache)"
	@echo "    - macOS: flush DNS (best effort); optional trustd restart message"

# -------------------------------------------------------------------
# Build / Run
# -------------------------------------------------------------------
build:
		dotnet build $(LOCAL_PROJ) -c $(CONFIG)

run:
		@echo "URL=$(URL)"
		@echo "REV_MODE=$(REV_MODE) (NoCheck|Online|Offline)"
		@echo "SOFTFAIL=$(SOFTFAIL) (true|false)"
		dotnet run --project $(LOCAL_PROJ) -c $(CONFIG) -- \
		  --url "$(URL)" \
		  --revocationMode $(REV_MODE) \
		  --revocationSoftFail $(SOFTFAIL) \
		  $(CA_ARGS)

clean:
		dotnet clean $(LOCAL_PROJ) -c $(CONFIG)

distclean:
		rm -rf ./src/Horacio-TLS-Lambda.Local/bin ./src/Horacio-TLS-Lambda.Local/obj

# -------------------------------------------------------------------
# Certificate / revocation cache clearing (OS-aware)
# -------------------------------------------------------------------
# Why this exists:
# - On Windows, CryptoAPI caches URL retrievals used during chain building
#   (CRL/OCSP/cert fetch). Clearing it prevents "it still fails" test confusion.
# - On macOS, there is no supported single CLI equivalent; we do a best-effort DNS
#   flush and optionally restart trustd (commented) for a stronger reset.

clean-cert-cache:
ifeq ($(OS),Windows_NT)
	@$(MAKE) clean-cert-cache-windows
else
	@UNAME_S=$$(uname -s); \
	if [ "$$UNAME_S" = "Darwin" ]; then \
		$(MAKE) clean-cert-cache-macos; \
	else \
		echo "Unsupported OS ($$UNAME_S) for cert cache clearing target. (No-op)"; \
	fi
endif

clean-cert-cache-windows:
	@echo "Clearing Windows CryptoAPI URL cache (CRL/OCSP/cert fetch cache)..."
	@certutil -urlcache * delete

clean-cert-cache-macos:
	@echo "Clearing macOS caches (best effort)..."
	@echo "Flushing DNS cache..."
	@sudo dscacheutil -flushcache || true
	@sudo killall -HUP mDNSResponder || true
	@echo "Note: macOS does not expose a supported single CLI to wipe OCSP/CRL caches globally."
	@echo "If needed, you may restart trustd (requires sudo): sudo launchctl kickstart -k system/com.apple.trustd"

# -------------------------------------------------------------------
# Optional: install Lambda test tool (local testing)
# -------------------------------------------------------------------
install-lambda-test-tool:
		dotnet tool install -g Amazon.Lambda.TestTool-8.0

local:
		dotnet build $(LAMBDA_PROJ) -c Debug
		cd $(LAMBDA_PROJ_DIR) && dotnet lambda-test-tool-8.0

# -------------------------------------------------------------------
# Optional: build/package the Lambda project for AWS
# -------------------------------------------------------------------
build-lambda:
		dotnet build ./src/Horacio-TLS-Lambda/Horacio-TLS-Lambda.csproj -c Release

package:
		cd ./src/Horacio-TLS-Lambda && dotnet lambda package -c Release --output-package Horacio-TLS-Lambda.zip

# -------------------------------------------------------------------
# Run shortcuts (revocation combinations)
# -------------------------------------------------------------------
run-nocheck:
		@$(MAKE) run REV_MODE=NoCheck SOFTFAIL=true

run-online-soft:
		@$(MAKE) run REV_MODE=Online SOFTFAIL=true

run-online-strict:
		@$(MAKE) run REV_MODE=Online SOFTFAIL=false

run-offline-soft:
		@$(MAKE) run REV_MODE=Offline SOFTFAIL=true

run-offline-strict:
		@$(MAKE) run REV_MODE=Offline SOFTFAIL=false

# -------------------------------------------------------------------
# Base URL shortcuts (edit URL_BASE to your endpoint)
# -------------------------------------------------------------------
URL_BASE := https://example.com

run-base-nocheck:
		@$(MAKE) run-nocheck URL=$(URL_BASE)

run-base-online-soft:
		@$(MAKE) run-online-soft URL=$(URL_BASE)

run-base-online-strict:
		@$(MAKE) run-online-strict URL=$(URL_BASE)
