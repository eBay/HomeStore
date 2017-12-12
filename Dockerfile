FROM ubuntu:16.04

RUN apt-get update && \
    apt-get install -y software-properties-common && \
    add-apt-repository ppa:ubuntu-toolchain-r/test && \
    apt-get update && \
    apt-get install -yq \
    g++-6 gdb valgrind \
    autoconf libtool automake \
    vim git patch \
    pkg-config \
    libssl-dev \
    libjemalloc-dev \
    libboost-all-dev \
    wget \
    curl && \
    update-alternatives --install /usr/bin/cpp cpp /usr/bin/cpp-6 60 && \
    update-alternatives --install /usr/bin/c++ c++ /usr/bin/g++-6 60 && \
    update-alternatives --install /usr/bin/g++ g++ /usr/bin/g++-6 60 && \
    update-alternatives --install /usr/bin/gcc gcc /usr/bin/gcc-6 60 && \
    update-alternatives --install /usr/bin/gcc-ar gcc-ar /usr/bin/gcc-ar-6 60 && \
    update-alternatives --install /usr/bin/gcc-nm gcc-nm /usr/bin/gcc-nm-6 60 && \
    update-alternatives --install /usr/bin/gcc-ranlib gcc-ranlib /usr/bin/gcc-ranlib-6 60 && \
    update-alternatives --install /usr/bin/gcov gcov /usr/bin/gcov-6 60

# Create a new Rails app under /src/my-app
RUN mkdir -p /src
RUN cd /tmp && \
	wget https://cmake.org/files/v3.9/cmake-3.9.6.tar.gz && \
	tar -xzvf cmake-3.9.6.tar.gz && \
	cd cmake-3.9.6 && \
	./bootstrap && \
	make -j 4 && \
	make install \
	
WORKDIR /src/

# Default command is to run a rails server on port 3000
#CMD ["rails", "server", "--binding", "0.0.0.0", "--port", "3000"]
ENTRYPOINT ["bash"]
