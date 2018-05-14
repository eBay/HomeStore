from conans import ConanFile, CMake

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.1.0"
    license = "Proprietary"
    description = "HomeStore"

    settings = "os", "compiler", "build_type", "arch"
    options = {"shared": [True, False]}

    requires = (("boost/[>=1.67,<2.0]@demo/dev"),
                ("folly/[>=0.58,<1.0]@demo/dev"),
                ("iomgr/[>=0.1,<1.0]@demo/dev"))

    build_requires = (("farmhash/[>=0.0,<1.0]@demo/dev"),
                      ("sds_logging/[>=0.1.2,<1.0]@demo/dev"))

    generators = "cmake"
    default_options = "shared=True"
    exports_sources = "*"

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()

    def package(self):
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.a", dst="lib", keep_path=False)
        self.copy("*.so", dst="lib", keep_path=False)
