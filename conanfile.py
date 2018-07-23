from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.6.0"
    license = "Proprietary"
    description = "HomeStore"
    url = "https://github.corp.ebay.com/SDS/Homestore"

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True]}

    requires = (("benchmark/1.4.1@oss/stable"),
                ("boost_heap/1.66.0@bincrafters/stable"),
                ("boost_uuid/1.66.0@bincrafters/stable"),
                ("double-conversion/3.0.0@bincrafters/stable"),
                ("farmhash/1.0.0@oss/stable"),
                ("folly/0.58.0@bincrafters/testing"),
                ("gperftools/2.7.0@oss/stable"),
                ("gtest/1.8.0@bincrafters/stable"),
                ("iomgr/1.1.2@sds/testing"))

    generators = "cmake"
    default_options = "shared=False", "fPIC=True"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        #cmake.test()

    def package(self):
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.hpp", dst="include", src="src", keep_path=True)
        self.copy("*/btree_node.cpp", dst="include", src="src", keep_path=True)
        self.copy("*cache/cache.cpp", dst="include", src="src", keep_path=True)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dll", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
        self.cpp_info.libs.extend(["aio"])
