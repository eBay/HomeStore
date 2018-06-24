from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.3.4"
    license = "Proprietary"
    description = "HomeStore"
    url = "https://github.corp.ebay.com/SDS/Homestore"

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False], "fPIC": [True]}

    requires = (("boost_heap/1.66.0@bincrafters/stable"),
                ("boost_uuid/1.66.0@bincrafters/stable"),
                ("double-conversion/3.0.0@bincrafters/stable"),
                ("farmhash/0.0.2@oss/stable"),
                ("folly/0.58.0@bincrafters/testing"),
                ("iomgr/1.0.5@sds/testing"),
                ("gperftools/2.7.0@oss/stable"),
                ("benchmark/1.4.1@oss/stable"))

    build_requires = (("sds_logging/1.0.0@sds/stable"),
                      ("gtest/1.8.0@bincrafters/stable"))

    generators = "cmake"
    default_options = "shared=False", "fPIC=True"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"

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
        self.cpp_info.libs.extend(["aio"])
