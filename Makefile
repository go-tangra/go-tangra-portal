GO        ?= go
PKGS      := $(shell $(GO) list ./... | grep -v /examples/)
COVER_OUT := coverage.out

.PHONY: lint vuln test test-integration cover fuzz generate shell-build redaction-scan perf-gate e2e compose-up compose-down

lint:
	$(GO) vet ./...
	staticcheck ./...
	gosec -quiet -exclude-generated -exclude-dir=shell -exclude-dir=examples/hello-module/ui ./...

vuln:
	../../scripts/vulncheck.sh

test:
	$(GO) test -race -count=1 ./...

test-integration:
	$(GO) test -race -count=1 -tags integration ./tests/integration/...

# Unit coverage is measured over packages that carry logic. Generated protobuf
# code, the SQL bindings (internal/store, */*db), the wiring (internal/app, cmd,
# examples) and the test packages are exercised by the tagged integration suite
# (make test-integration) and are excluded from the unit gate on purpose.
COVERPKG := $(shell $(GO) list ./... | grep -v -E '/api/proto/|/echov1$$|/internal/store$$|/internal/storeadapter$$|/internal/memstore$$|db$$|/internal/app$$|/cmd/|/examples/|/tests/|/shell$$' | paste -sd, -)

cover:
	$(GO) test -count=1 -coverprofile=$(COVER_OUT) -coverpkg=$(COVERPKG) $(PKGS)
	./scripts/coverage-gate.sh $(COVER_OUT)

fuzz:
	for f in FuzzManifest FuzzCASLRule FuzzPrefix FuzzRoutePath FuzzRegisterRequest FuzzGRPCWebFrame FuzzBearerToken FuzzPathNormalize FuzzAbilityPack; do \
	  $(GO) test -run xxx -fuzz=$$f -fuzztime=20s ./tests/fuzz/ || exit 1; done

generate:
	cd sdk && buf generate

shell-build:
	cd shell && npm ci && npm run build

redaction-scan:
	./scripts/redaction-scan.sh

e2e:
	cd shell && npx playwright test

compose-up:
	docker compose -f deploy/compose.yaml up -d

compose-down:
	docker compose -f deploy/compose.yaml down -v

perf-gate:
	./scripts/perf-gate.sh
