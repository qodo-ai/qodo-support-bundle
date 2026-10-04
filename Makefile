VERSION ?= dev
MODULE := github.com/qodo-ai/qodo-support-bundle
PYTHON ?= python3
TEST_VENV ?= .test-venv
override QODO_SUPPORT_BUNDLE_VERSION := $(value VERSION)
export QODO_SUPPORT_BUNDLE_VERSION
LDFLAGS := -s -w -X $(MODULE)/internal/app.Version=$$QODO_SUPPORT_BUNDLE_VERSION

.PHONY: build test test-installers test-python-deps format-check release clean

build:
	mkdir -p dist
	go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle ./cmd/qodo-support-bundle

test: format-check test-installers
	@test -x "$(TEST_VENV)/bin/python3" || { \
		echo "Missing Python test environment. Run 'make test-python-deps' first." >&2; \
		exit 1; \
	}
	PATH="$(CURDIR)/$(TEST_VENV)/bin:$$PATH" go test -race ./...
	go vet ./...

test-installers:
	shellcheck install.sh tests/install_sh_test.sh scripts/*.sh
	sh -n install.sh
	sh -n tests/install_sh_test.sh
	for script in scripts/*.sh; do sh -n "$$script"; done
	sh tests/install_sh_test.sh

test-python-deps:
	@test -x "$(TEST_VENV)/bin/python3" || "$(PYTHON)" -m venv "$(TEST_VENV)"
	"$(TEST_VENV)/bin/python3" -m pip install \
		--disable-pip-version-check \
		--require-hashes \
		--only-binary=:all: \
		-r test-requirements.txt

format-check:
	@files="$$(git ls-files --cached --others --exclude-standard '*.go' | \
		while IFS= read -r file; do test ! -f "$$file" || echo "$$file"; done)"; \
	if [ -n "$$files" ]; then \
		unformatted="$$(gofmt -l $$files)"; \
		test -z "$$unformatted" || { echo "Run gofmt on:"; echo "$$unformatted"; exit 1; }; \
	fi

release: clean
	mkdir -p dist
	GOOS=linux GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle-linux-amd64 ./cmd/qodo-support-bundle
	GOOS=linux GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle-linux-arm64 ./cmd/qodo-support-bundle
	GOOS=darwin GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle-darwin-amd64 ./cmd/qodo-support-bundle
	GOOS=darwin GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle-darwin-arm64 ./cmd/qodo-support-bundle
	GOOS=windows GOARCH=amd64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle-windows-amd64.exe ./cmd/qodo-support-bundle
	GOOS=windows GOARCH=arm64 go build -trimpath -ldflags="$(LDFLAGS)" -o dist/qodo-support-bundle-windows-arm64.exe ./cmd/qodo-support-bundle
	cp install.sh install.ps1 dist/
	cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum qodo-support-bundle-* > checksums.sha256; else shasum -a 256 qodo-support-bundle-* > checksums.sha256; fi
	cd dist && if command -v sha256sum >/dev/null 2>&1; then sha256sum install.sh install.ps1 > installer-checksums.sha256; else shasum -a 256 install.sh install.ps1 > installer-checksums.sha256; fi

clean:
	rm -rf dist
