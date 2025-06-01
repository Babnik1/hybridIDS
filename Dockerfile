# Using Ubuntu 22.04
FROM ubuntu:22.04

# Disable apt regime
ENV DEBIAN_FRONTEND=noninteractive

# Install libs
RUN apt-get update && apt-get install -y \
	build-essential \
	cmake \
	python3-pip \
	git \
	curl \
	iproute2 \
	iptables \
	nano \
	vim \
	pkg-config \
	libmnl-dev \
	libnftnl-dev \
	libpcap-dev \
	&& pip3 install --no-cache-dir conan \
	&& apt-get clean && rm -rf /var/lib/apt/lists/*

# Set the working directory
WORKDIR /app

# Copy the project into the container
COPY . .

# Build the project
RUN conan profile detect && \
	conan install . --output-folder=build --build=missing && \
	cmake -S . -B build -DCMAKE_TOOLCHAIN_FILE=build/build/Release/generators/conan_toolchain.cmake -DCMAKE_BUILD_TYPE=Release && \
	cmake --build build
