.PHONY: help print build test cover clean distclean package

BOLD      = \033[1m
UNDERLINE = \033[4m
BLUE      = \033[36m
RESET     = \033[0m

VERSION := $(shell git describe --tags --always --dirty="-dev")
DATE    := $(shell date -u '+%Y-%m-%d-%H%M UTC')
ARCHS   ?= amd64 arm64

Q ?= @

## Show usage information for this Makefile
help:
	@printf "$(BOLD)chl-byp-srv$(RESET)\n\n"
	@printf "$(UNDERLINE)Available Tasks$(RESET)\n\n"
	@awk -F \
		':|##' '/^##/ {c=$$2; getline; printf "$(BLUE)%10s$(RESET) %s\n", $$1, c}' \
		$(MAKEFILE_LIST)
	@printf "\n"

## print command
print-command:
	$Q@printf "GOARCH=$(ARCH) CGO_ENABLED=1 go build -ldflags='-X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"' -o bin/chl-byp-srv ./server"

## Build executable
build:
	$Q# ARCH is set from `package`.
	$Q# Alternatively, run `make ARCH=<amd64|arm64> build` to override here.
	$QGOARCH=$(ARCH) CGO_ENABLED=1 go build \
		-ldflags='-X "main.Version=$(VERSION)" -X "main.BuildTime=$(DATE)"' \
		-o bin/chl-byp-srv \
		./server

## Run tests
test: build
	PATH="${PATH}:${PWD}/bin" && GOCACHE=off && go test -v -race ./...

## Generate cover report
cover:
	$Qmkdir -p .cover
	$Qrm -f .cover/*.out .cover/all.merged .cover/all.html
	$Qfor pkg in $$(go list ./...); do \
		go test -coverprofile=.cover/`echo $$pkg|tr "/" "_"`.out $$pkg; \
	done
	$Qecho 'mode: set' > .cover/all.merged
	$Qgrep -h -v "mode: set" .cover/*.out >> .cover/all.merged
ifndef CI
	$Qgo tool cover -html .cover/all.merged
else
	$Qgo tool cover -html .cover/all.merged -o .cover/all.html
endif

## Clean build files
clean:
	$Qrm -rf bin