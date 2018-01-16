#!/usr/bin/env bash
CMAKE_VERSION=3.9.6
BOOST_VERSION=1.65.1
FOLLY_VERSION=2017.12.25.00
FARMHASH_COMMIT=2f0e005b81e296fa6963e395626137cf729b710c
BENCHMARK_VERSION=1.3.0
LIBGFLAGS_VERSION=2.2.0
GLOG_RELEASE=0.3.5
GPERF_RELEASE=2.6.3
GTEST_VERSION=1.8.0

# Determine the OS type
rel=`uname -a | awk '{print $1}'`
if [ $rel = "Linux" ] ; then
	os_type="linux"
elif [ $rel = "Darwin" ] ; then
	os_type="mac"
else
	os_type="unknown"
fi

JOBS=16

proj_dir=`pwd`
deps_build=$proj_dir/"deps_build/$os_type/"
deps_prefix=$proj_dir/"deps_prefix/$os_type/"

mkdir -p $deps_build
mkdir -p $deps_prefix
cd $deps_build

function library() {
    name=$1 # - library name; becomes directory prefix
    version=$2 # - library version or commit or tag; becomes directory suffix
    url=$3 # - URL; must have the name and version already expanded
    dirname=${4:-$name-$version} # - output directory name
    branch=${5:-master} #- parameter for git download method

    if [ ! -e $dirname -o ! -e $dirname/build_success ]; then
        rm -rf $dirname
        echo "Fetching $dirname"

        case $url in
            *.tar.gz)
                wget --max-redirect=5 -O $dirname.tar.gz $url
                tar zxf $dirname.tar.gz
                test -d $dirname
                cd $dirname;;
            *.h)
                mkdir $dirname
                wget --max-redirect=5 --directory-prefix=$dirname $url
                cd $dirname;;
            *.git)
                git clone -b $branch $url $dirname
                cd $dirname
                git cat-file -e $version^{commit} && git checkout $version || true;;
            *)
              echo Unable to derive download method from url $url
              exit 1;;
        esac

        $name # invoke the build function

        cd $deps_build
        touch $dirname/build_success
	else
		echo "${name} ${version} is already installed"
    fi
}

function is_installed_by_brew() {
    name=$1
    version=$2

    fn_ret=""
    installed_pkgs=`brew list --versions | grep $name 2>/dev/null`
    if [ $? -eq 0 ] ; then
        for v in `echo $installed_pkgs`; do
            if [ $v == $version ] ; then
                fn_ret=$v
                break
            fi
        done
    fi
}

function install_thru_brew() {
    name=$1
    version=${2-$name}

    is_installed_by_brew $name $version
    if [ -z "$fn_ret" ] ; then
        brew install $name
        brew link $name
    else
        echo "$name $version is already installed"
    fi
}

##################### CMake #########################
install_cmake() {
	ver=`cmake --version 2>/dev/null | grep version | awk '{print $3}'`
	if [ ! -z "$ver" -a "$ver" = "$CMAKE_VERSION" ] ; then
		echo "CMake $CMAKE_VERSION is already installed"
		return
	fi

	src_dir=$deps_build/cmake-${CMAKE_VERSION}/
	mkdir -p $src_dir && cd $src_dir
	wget https://cmake.org/files/v3.9/cmake-${CMAKE_VERSION}.tar.gz
	tar -xzvf cmake-${CMAKE_VERSION}.tar.gz
	cd cmake-${CMAKE_VERSION}
	./bootstrap 
	make -j 16
	make install

	touch $src_dir/build_success
}
#install_cmake

##################### BOOST #########################
boost() {
	cp -r boost $deps_prefix/include/
}
boost_ver=`echo ${BOOST_VERSION} | sed 's/\./_/g'`
library boost ${BOOST_VERSION} https://dl.bintray.com/boostorg/release/${BOOST_VERSION}/source/boost_${boost_ver}.tar.gz boost_${boost_ver}

##################### GFLAGS #########################
gflags() {
    mkdir cmake.build
    cd cmake.build
    #cmake  -DCMAKE_INSTALL_PREFIX:PATH=$deps_prefix -DBUILD_SHARED_LIBS=1 ..
    cmake -DBUILD_SHARED_LIBS=1 ..
    make -j$JOBS install
};
library gflags ${LIBGFLAGS_VERSION} https://github.com/gflags/gflags/archive/v${LIBGFLAGS_VERSION}.tar.gz

##################### GLOG #########################
glog () {
    echo "Applying change patches"
    patch -p1 -f < $proj_dir/patches/glog/custom_log.patch
    patch -p1 -f < $proj_dir/patches/glog/fix_race.patch

    aclocal
    automake --add-missing
    #./configure --prefix=$deps_prefix
    ./configure
    make -j$JOBS install
}
library glog ${GLOG_RELEASE} https://github.com/google/glog/archive/v${GLOG_RELEASE}.tar.gz

##################### Folly #########################
folly() {
	apt-get install	-y automake \
		autoconf \
		autoconf-archive \
		libtool \
		libboost-all-dev \
		libevent-dev \
		libdouble-conversion-dev \
		liblz4-dev \
		liblzma-dev \
		libsnappy-dev \
		zlib1g-dev \
		binutils-dev \
		libjemalloc-dev \
		libssl-dev \
		pkg-config \
		libunwind8-dev \
		libelf-dev \
		libdwarf-dev \
		libiberty-dev

	cd folly/
	autoreconf -ivf
	#./configure --prefix=$deps_prefix
	./configure
	make -j$JOBS
	make check
	make install
}
if [ $os_type = "mac" ] ; then
    install_thru_brew folly ${FOLLY_VERSION}
else
	library folly ${FOLLY_VERSION} https://github.com/facebook/folly/archive/v${FOLLY_VERSION}.tar.gz
fi

##################### FarmHash #########################
farmhash () {
    aclocal
    automake --add-missing
    #./configure --prefix=$deps_prefix CXXFLAGS="-g -mavx -maes -O3"
    ./configure CXXFLAGS="-g -mavx -maes -O3"
    make -j$JOBS all
    make install
}
library farmhash $FARMHASH_COMMIT https://github.com/google/farmhash.git

##################### Google Benchmark #########################
benchmark() {
	cd benchmark
	mkdir build
	cd build
	cmake .. -DCMAKE_BUILD_TYPE=RELEASE
	make -j$JOBS
	make install
}
library benchmark $BENCHMARK_VERSION https://github.com/google/benchmark/archive/v${BENCHMARK_VERSION}.tar.gz

##################### GPERF #########################
gperf() {
if [ $os_type = "mac" ] ; then
	install_thru_brew gperftools ${GPERF_RELEASE}
else
	apt-get install libgoogle-perftools-dev
fi
}
gperf

##################### Google Test #########################
gtest() {
    cd googletest
    #cmake -DCMAKE_INSTALL_PREFIX:PATH=$deps_prefix -DBUILD_SHARED_LIBS=ON .
    cmake -DBUILD_SHARED_LIBS=ON .
    make
    make install
}
library gtest $GTEST_VERSION https://github.com/google/googletest/archive/release-${GTEST_VERSION}.tar.gz googletest-release-${GTEST_VERSION}
