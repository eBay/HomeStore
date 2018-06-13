from conans import ConanFile, CMake, tools
from conans.tools import os_info

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.3.2"
    license = "Proprietary"
    description = "HomeStore"
    url = "https://github.corp.ebay.com/SDS/Homestore"

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True]}

    requires = (("boost/1.67.0@oss/stable"),
                ("farmhash/0.0.2@oss/stable"),
                ("folly/0.58.0@oss/stable"),
                ("iomgr/[>=1.0.4,<2.0]@demo/dev"),
                ("benchmark/1.4.1@oss/stable"))

    build_requires = (("sds_logging/1.0.0@sds/stable"),
                      ("gtest/1.8.0@oss/stable"))

    generators = "cmake"
    default_options = "shared=True", "fPIC=True"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"

    # These are not proper Conan dependencies, but support building
    # packages outside the official SDS build image. If you want to support
    # an OS/Platform that isn't listed, you'll need to add it yourself
    def system_requirements(self):
        pkgs = list()
        if os_info.linux_distro == "ubuntu":
            pkgs.extend(("libgoogle-perftools-dev",
                         "libaio-dev",
                         "libdouble-conversion-dev",
                         "libevent-dev",
                         "libgflags-dev"))
            if os_info.os_version < "17":
                pkgs.append("g++-5")
            elif os_info.os_version < "18":
                pkgs.append("g++-6")
            elif os_info.os_version < "19":
                pkgs.append("g++-7")
            else:
                pkgs.append("g++")

        installer = tools.SystemPackageTool()
        for pkg in pkgs:
            installer.install(packages=pkg, update=False)

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        cmake.test()

    def package(self):
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.hpp", dst="include", src="src", keep_path=True)
        self.copy("*/btree_node.cpp", dst="include", src="src", keep_path=True)
        self.copy("*cache/cache.cpp", dst="include", src="src", keep_path=True)
        if self.options.shared:
            self.copy("*.so", dst="lib", keep_path=False)
        else:
            self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
        self.cpp_info.libs.extend(["aio", "double-conversion"])
