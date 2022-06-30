+++
title = 'Using Makefiles with Go'
date = '2019-12-11'
author = 'Nate Catelli'
tags = [
    "make",
    "golang",
]
description = 'Using make to wrap golang with extra functionality.'
draft = true
+++

### Introduction

One of my favorite features of golang is its simple toolchain for builds. However at times, I've wished that I could easily add tasks to a build step. Using GNU Make, I've found that I can quickly and easily wrap the go toolchain in a consistent way that leaves plenty of room for customization.

### Wrapping Common Go Commands

Primarily, I've been able to get away with 1:1 mapping of many of the go tool chain directly behind corresponding make commands.

The `fmt` command is mostly a copy paste of the corresponding go command. However, by leveraging some core functionality within make, we are able to begin defining dependency chains in other steps that allow us to insure that code is formatted, linted and tested prior to builds.

```Makefile
APP_NAME=examplepkg
IMG_NAME="ncatelli/examplepkg"
PKG="github.com/ncatelli/examplepkg"

build: | fmt lint test
 go build

build-docker: | fmt lint test
 docker build -t ${IMG_NAME}:latest .

test:
 go test -race -cover ./...

fmt:
 test -z $(shell go fmt ./...)

clean-docker:
 @type docker >/dev/null 2>&1 && \
 docker rmi -f ${IMG_NAME}:latest || \
 true

clean: clean-docker
 @rm -f ${APP_NAME} || true

lint:
 golint -set_exit_status ./...
```

### Leveraging go modules

By leveraging go modules, we can also insure that each build will have the required dependencies for our toolchain, an example being the golint command as can be seen in the below example `go.mod` file.

```go
module github.com/ncatelli/examplepkg

require (
 golang.org/x/lint v0.0.0-20191125180803-fdd1cda4f05f // indirect
)

go 1.13
```

### Use With cGo

Though simply wrapping the go toolchain appears to add very little value while adding additional complexity, we begin to see greater benefit when dealing with additional external C libraries. My first use of makefiles with go was while working with [libfreeipmi](https://www.gnu.org/software/freeipmi/). At the time, I was attempting to implement golang bindings for a limited subset of libfreeipmi which required building the shared objects for libfreeipmi from source. Adding this build process to the makefile simplified the building of the library and was easily defined by adding a few extra blocks:

```Makefile
PKG="github.com/ncatelli/examplepkg"
BUILDOPTS=--ldflags '-extldflags "-static"'
DEPSCONFOPTS=--enable-static --without-encryption

build: | test
  go build $(BUILDOPTS) $(PKG)

test: | fmt deps
  go test $(BUILDOPTS) $(PKG) -v

fmt:
  go fmt $(PKG)

doc: | fmt
  godoc $(PKG) > $(GOPATH)/src/$(PKG)/README.md

deps:
  cd libs/freeipmi; \
  ./autogen.sh && \
  ./configure $(DEPSCONFOPTS) && \
  make

clean:
  cd libs/freeipmi; \
  make clean
```

### Leveraging Docker Environments in Makefiles

If you are not using cGo, you can still benefit from the Makefiles abstraction by wrapping a docker build environment. I've included an example of a Makefile from our pasteclick project that wraps a small docker environment with libmagic installed.

```MakeFile
PKG="gitlab.packetfire.org/Tiksi/paste-click"
GOENV="ncatelli/golang:1.9.2-libmagic"

build: | test
  docker run -it --rm -u root -v `pwd`:/go/src/$(PKG) $(GOENV) go build $(PKG)

fmt:
  docker run -it --rm -u root -v `pwd`:/go/src/$(PKG) $(GOENV) go fmt $(PKG)

test: | fmt
  docker run -it --rm -u root -v `pwd`:/go/src/$(PKG) $(GOENV) go test $(PKG)
```

Leveraging a container and make, one is able to provide a consistent build process in a build environment that is repeatable across platforms.

### Summary

While the go toolchain is sufficient for purely go packages, leveraging simple makefiles to augment this toolchain with additional tasks is a simple and viable option for keeping your build processes down to a few concise commands.
