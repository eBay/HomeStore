from conans import ConanFile, CMake

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.1.0"
    license = "Proprietary"
    description = "HomeStore"

    settings = "os", "compiler", "build_type", "arch"

    requires = (("folly/[>=0.58,<1.0]@demo/dev"),
                ("boost/[>=1.67,<2.0]@demo/dev"))

    generators = "cmake"
    exports_sources = "*"

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
