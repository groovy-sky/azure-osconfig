#!/bin/sh
# Installs build essentials for the Mariner distribution
tdnf -y update
tdnf -y install git \
                cmake \
                build-essential \
                tar \
                gtest \
                gtest-devel \
                gmock \
                gmock-devel \
                curl \
                openssl \
                rapidjson \
                curl-devel \
                openssl-devel \
                util-linux-devel