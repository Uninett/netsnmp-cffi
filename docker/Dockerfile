# Defines a build environment for binary wheels of netsnmp-cffi This runs on an
# older version of AlmaLinux in order to support older versions of glibc, but
# that means we also have to backport Net-SNMP 5.9 from a newer AlmaLinux
# version, since netsnmp-cffi will not properly support Net-SNMP 5.8, which is
# what this version of AlmaLinux provides.
FROM quay.io/pypa/manylinux_2_28_x86_64

# Install necessary build tools
RUN yum update -y && \
    yum install -y wget rpm-build rpmdevtools yum-utils gcc gcc-toolset-14-annobin-plugin-gcc.x86_64 make && \
    yum groupinstall -y "Development Tools"

ENV NET_SNMP_VERSION=5.9.1-17

RUN rpmdev-setuptree

# Fetch net-snmp from a newer AlmaLinux repository
RUN wget https://repo.almalinux.org/vault/9/AppStream/Source/Packages/net-snmp-${NET_SNMP_VERSION}.el9.src.rpm && \
    rpm -ivh net-snmp-${NET_SNMP_VERSION}.el9.src.rpm

# Install the build dependencies
RUN yum-builddep -y ~/rpmbuild/SPECS/net-snmp.spec

# Net-SNMP tests are hardcoded to expect autconf 2.69, but this build process
# provides 2.72, so we need to produce a new SRPM with our own patches :P
# https://github.com/net-snmp/net-snmp/commit/215695f2307dc02399fa2bb789c2b1e790d8551e is nice reference here.
COPY *.patch /tmp

# Patch the rpm spec file, build a new SRPM, build new binary packages and install those
RUN cp /tmp/net-snmp-5.9-autoconf-version.patch ~/rpmbuild/SOURCES/ && \
    cd ~/rpmbuild/SPECS && \
    patch -p0 < /tmp/net-snmp-buildspec.patch && \
    rpmbuild -bs net-snmp.spec
RUN rpmbuild --rebuild --nocheck ~/rpmbuild/SRPMS/net-snmp-${NET_SNMP_VERSION}.el8.src.rpm
RUN yum localinstall -y ~/rpmbuild/RPMS/x86_64/net-snmp-*.rpm

# Clean up
RUN rm -rf ~/rpmbuild && \
    yum clean all

# If net-snmp were already available in the correct version on AlmaLinux, all
# we would need was the next line:
#RUN yum install -y net-snmp-devel.x86_64

ENV HOME=/tmp
