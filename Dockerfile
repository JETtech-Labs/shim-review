## Create a docker image for reproducible build of shim binaries
FROM ubuntu:22.04

# install required packages
RUN apt update && \
    apt install -y \
    build-essential git patch make gcc binutils dos2unix xxd wget openssl gnupg2

RUN adduser --disabled-password --gecos '' jet \
    && adduser jet sudo \
    && echo '%sudo ALL=(ALL:ALL) ALL' >> /etc/sudoers

USER jet
WORKDIR /home/jet

# copy shim binaries provided for review
RUN mkdir -p shim-review
COPY shimx64.efi shim-review

# copy our CA certificate
COPY cert.der shim-review

# copy our SBAT file
COPY sbat.jettech.csv shim-review

# copy our patches if any
# COPY patches shim-review

# download upstream traball
ARG SHIM_VERSION=16.0
ARG COMMIT_ID=18d98bfb34be583a5fe2987542e4b15e0db9cb61


# download upstream traball
RUN wget https://github.com/rhboot/shim/releases/download/${SHIM_VERSION}/shim-${SHIM_VERSION}.tar.bz2\
    && tar -xjvf shim-${SHIM_VERSION}.tar.bz2
WORKDIR /home/jet/shim-${SHIM_VERSION}


# apply our patches
RUN for i in $(ls ~/shim-review/*.patch); do patch -p1 < $i; done

# copy our sbat.csv
RUN cp -f ~/shim-review/sbat.jettech.csv data/sbat.csv

# avoid BuildMachine difference breaking resulting sha256sum
ENV SOURCE_DATE_EPOCH=yes

# note Below COMMIT_ID cooresponds to shimt git commit
RUN mkdir -p build-x64
RUN cd build-x64 && \
    make VENDOR_CERT_FILE=/home/jet/shim-review/cert.der TOPDIR=.. \
    ARCH="x86_64" \
    COMMIT_ID="${COMMIT_ID}" \
    -f ../Makefile 2>&1 | tee /home/jet/build-x64.log

# Verify checksums
WORKDIR /home/jet
RUN sha256sum shim-review/*.efi shim-${SHIM_VERSION}/build-*/shim*.efi

