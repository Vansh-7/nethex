# 1. Start with a lightweight, stable Linux foundation
FROM ubuntu:22.04

# 2. Prevent Ubuntu from pausing the build to ask for timezone inputs
ENV DEBIAN_FRONTEND=noninteractive

# 3. Install our exact build tools and dependencies (xxHash)
RUN apt-get update && apt-get install -y \
    build-essential \
    cmake \
    libxxhash-dev \
    && rm -rf /var/lib/apt/lists/*

# 4. Create a working directory inside the container
WORKDIR /app

# 5. Copy all our NetHex code from our computer into the container
COPY . /app

# 6. The standard CMake build sequence (Out-of-source build)
RUN mkdir build && cd build && cmake .. && make

# 7. Set the default command to run our DPI engine when the container starts
# main() requires argv[1] (a .pcap file) or it exits immediately with a usage error,
# so we use ENTRYPOINT + CMD: this runs the bundled sample.pcap by default,
# but still lets callers override it, e.g.:
#   docker run nethex-image                -> analyzes sample.pcap
#   docker run nethex-image my_capture.pcap -> analyzes my_capture.pcap
ENTRYPOINT ["./build/nethex"]
CMD ["sample.pcap"]