from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.1.6"
    license = "Proprietary"
    description = "HomeStore"

    settings = {"os": ["Linux"],
                "compiler": None,
                "build_type": None,
                "arch": None}
    options = {"shared": [True, False], "fPIC": [True]}

    requires = (("boost/[>=1.67,<2.0]@demo/dev"),
                ("farmhash/[>=0.0,<1.0]@demo/dev"),
                ("folly/[>=0.58,<1.0]@demo/dev"),
                ("iomgr/[>=1.0,<2.0]@demo/dev"))

    build_requires = (("sds_logging/[>=0.1.2,<1.0]@demo/dev"))

    generators = "cmake"
    default_options = "shared=True", "fPIC=True"
    exports_sources = "*"

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.hpp", dst="include", src="src", keep_path=True)
        self.copy("*/btree_node.cpp", dst="include", src="src", keep_path=True)
        self.copy("*cache/cache.cpp", dst="include", src="src", keep_path=True)
        self.copy("*.so", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
        self.cpp_info.libs.extend(["aio", "double-conversion"])
