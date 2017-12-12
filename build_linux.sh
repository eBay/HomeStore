export LD_LIBRARY_PATH=/src/workspace_c++/OmStore/deps_prefix/linux/lib/:/usr/local/lib:/usr/lib:$LD_LIBRARY_PATH
build_type="debug"
if [ ! -z "$1" ] ; then
	if [ $1 = "-r" ] ; then
		build_type="release"
		shift;
	elif [ $1 = "-d" ] ; then
		shift;
	fi
fi

if [ $build_type = "release" ] ; then
	cmake -DCMAKE_BUILD_TYPE=Release -DNDEBUG=1 -O2 -G "CodeBlocks - Unix Makefiles" -Bcmake-build-release/linux -H.
	make VERBOSE=1 -C cmake-build-release/linux $*
else
	cmake -DCMAKE_BUILD_TYPE=Debug -G "CodeBlocks - Unix Makefiles" -Bcmake-build-debug/linux -H.
	make VERBOSE=1 -C cmake-build-debug/linux $*
fi
