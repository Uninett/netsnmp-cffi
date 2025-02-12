# This Makefile simplifies manylinux binary wheel builds for uploads to PyPI
# See https://github.com/pypa/manylinux
.PHONY: all build docker-build py%
IMAGENAME := netsnmp-cffi-build
UID := $(shell id -u)

all: build

build: docker-build py39 py310 py311 py312
	docker run -u $(UID) -v $(PWD):/src -v $(PWD)/dist:/output $(IMAGENAME) /bin/bash -c "auditwheel repair /output/netsnmp_cffi**-linux*whl -w /output"

py%: PYVER=$(subst py,cp,$@)
py%:
	@echo "Building for $@"
	docker run -u $(UID) -v $(PWD):/src -v $(PWD)/dist:/output $(IMAGENAME) /opt/python/$(PYVER)-$(PYVER)/bin/pip wheel /src -w /output

docker-build:
	cd docker ; docker build -t $(IMAGENAME) .
