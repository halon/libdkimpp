FROM ubuntu:20.04
LABEL org.opencontainers.image.authors="root@halon.io"

ARG DEBIAN_FRONTEND=noninteractive

RUN apt-get update
RUN apt-get install -y git g++ cmake pkg-config libsodium-dev libssl-dev libcppunit-dev cppunit++