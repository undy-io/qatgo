GO ?= $(shell command -v go 2>/dev/null)
ifeq ($(strip $(GO)),)
GO := $(firstword $(wildcard ../.tools/go*/go/bin/go))
endif
export GOCACHE ?= /tmp/qatgo-build-cache
export GOMODCACHE ?= /tmp/qatgo-mod-cache

# Consumers can keep the driver source in a separate checkout. Retain the
# original nested-layout convenience when this module lives inside it.
QAT_SOURCE ?= $(if $(wildcard ../quickassist/include/cpa.h),$(abspath ..))
ifneq ($(strip $(QAT_SOURCE)),)
export CGO_CFLAGS += -I$(QAT_SOURCE)/quickassist/include -I$(QAT_SOURCE)/quickassist/include/lac -I$(QAT_SOURCE)/quickassist/include/icp -I$(QAT_SOURCE)/quickassist/utilities/libusdm_drv
endif

.PHONY: all build test hardware-test race-test vet clean
all: build
build:
	$(GO) build -o qatbench ./cmd/qatbench
	$(GO) build -o hashstdin ./cmd/hashstdin
	$(GO) build -o qatalloc ./cmd/qatalloc
	$(GO) build -o qatparallel ./cmd/qatparallel
test:
	$(GO) test ./...
hardware-test:
	$(GO) test -c -o qatgo.test
	sudo env QATGO_TEST_HW=1 ./qatgo.test -test.v -test.timeout=90s
race-test:
	GOEXPERIMENT=cgocheck2 $(GO) test -race -c -o qatgo-race.test
	sudo env QATGO_TEST_HW=1 ./qatgo-race.test -test.v -test.timeout=90s
vet:
	$(GO) vet ./...
clean:
	rm -f qatbench hashstdin qatalloc qatparallel qatgo.test qatgo-race.test
