GOLIB ?= golib

.PHONY: check check-full ci fast-check planning-check check-online cohesion inventory repository-check runtime-check native-runtime-check

# Standalone routes retain the unconditional whole-tree secret scan.
check ci fast-check:
	$(MAKE) planning-check
	$(GOLIB) secrets check

# Native adapters qualify their external services separately.
runtime-check:
	go test -race -count=1 -timeout=120s ./...
	go vet ./...

native-runtime-check:
	cd postgres && go test -mod=readonly -race -count=1 -timeout=120s ./...
	cd postgres && go vet -mod=readonly -tags=integration ./...
	cd postgres && go mod verify

# CI selects its immutable changed-content secret scan separately.
planning-check:
	$(GOLIB) config validate
	$(GOLIB) repository check
	$(GOLIB) cohesion check
	$(GOLIB) specification check
	$(GOLIB) docs check --local

check-online: check
	$(GOLIB) specification check --online

# Optional broad documentation assurance; not an ordinary CI prerequisite.
check-full:
	$(GOLIB) check --all

cohesion:
	$(GOLIB) cohesion check

inventory repository-check:
	$(GOLIB) repository check
