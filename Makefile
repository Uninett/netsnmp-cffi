# This Makefile simplifies manylinux binary wheel builds for uploads to PyPI
# See https://github.com/pypa/manylinux
.PHONY: all build docker-build sdist py%
IMAGENAME := netsnmp-cffi-build
UID := $(shell id -u)
# The sdist is built from a pristine checkout of HEAD, so untracked files in
# the working tree cannot leak into it.
CLEANSRC := build/clean-src
SDISTDIR := build/sdist

all: build

build: dist docker-build sdist py39 py310 py311 py312 py313 py314
	docker run -u $(UID) -v $(PWD):/src -v $(PWD)/dist:/output $(IMAGENAME) /bin/bash -c "auditwheel repair /output/netsnmp_cffi**-linux*whl -w /output"

sdist: dist
	-git worktree remove --force $(CLEANSRC) 2>/dev/null
	rm -rf $(SDISTDIR)
	git worktree add --detach $(CLEANSRC) HEAD
	uv build --sdist --out-dir $(SDISTDIR) $(CLEANSRC)
	git worktree remove --force $(CLEANSRC)
	cp $(SDISTDIR)/*.tar.gz dist/

py%: PYVER=$(subst py,cp,$@)
py%:
	@echo "Building for $@"
	docker run -u $(UID) -v $(PWD):/src -v $(PWD)/dist:/output $(IMAGENAME) /opt/python/$(PYVER)-$(PYVER)/bin/pip wheel /src -w /output

docker-build:
	cd docker ; docker build -t $(IMAGENAME) .

dist:
	# Ensure dist directory is created and owned by the current user
	mkdir -p dist
