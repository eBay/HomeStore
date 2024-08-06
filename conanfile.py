from conan import ConanFile
from conan.errors import ConanInvalidConfiguration
from conan.tools.build import check_min_cppstd
from conan.tools.cmake import CMakeToolchain, CMakeDeps, CMake, cmake_layout
from conan.tools.files import copy
from os.path import join

required_conan_version = ">=1.60.0"

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "6.4.37"

    homepage = "https://github.com/eBay/Homestore"
    description = "HomeStore Storage Engine"
    topics = ("ebay", "nublox")
    url = "https://github.com/eBay/Homestore"
    license = "Apache-2.0"

    settings = "arch", "os", "compiler", "build_type"

    options = {
                "shared": ['True', 'False'],
                "fPIC": ['True', 'False'],
                "coverage": ['True', 'False'],
                "sanitize": ['True', 'False'],
                "testing" : ['full', 'min', 'off', 'epoll_mode', 'spdk_mode'],
            }
    default_options = {
                'shared':       False,
                'fPIC':         True,
                'coverage':     False,
                'sanitize':     False,
                'testing':      'epoll_mode',
            }

    exports_sources = "cmake/*", "src/*", "CMakeLists.txt", "test_wrap.sh", "LICENSE"
    keep_imports = True

    def configure(self):
        if self.options.shared:
            self.options.rm_safe("fPIC")
        if self.settings.build_type == "Debug":
            if self.options.coverage and self.options.sanitize:
                raise ConanInvalidConfiguration("Sanitizer does not work with Code Coverage!")
            if self.conf.get("tools.build:skip_test", default=False):
                if self.options.coverage or self.options.sanitize:
                    raise ConanInvalidConfiguration("Coverage/Sanitizer requires Testing!")

    def build_requirements(self):
        self.test_requires("benchmark/1.8.2")
        self.test_requires("gtest/1.14.0")

    def requirements(self):
        self.requires("iomgr/[^11.3]@oss/master", transitive_headers=True)
        self.requires("sisl/[^12.2]@oss/master", transitive_headers=True)
        self.requires("nuraft_mesg/[^3.4]@oss/main", transitive_headers=True)

        self.requires("farmhash/cci.20190513@", transitive_headers=True)
        if self.settings.arch in ['x86', 'x86_64']:
            self.requires("isa-l/2.30.0", transitive_headers=True)

    def imports(self):
        self.copy(root_package="sisl", pattern="*", dst="bin/scripts/python/flip/", src="bindings/flip/python/", keep_path=False)

    def layout(self):
        cmake_layout(self)

    def generate(self):
        # This generates "conan_toolchain.cmake" in self.generators_folder
        tc = CMakeToolchain(self)
        if self.options.testing != "off":
            tc.variables["TEST_TARGET"] = self.options.testing
        tc.variables["CONAN_CMAKE_SILENT_OUTPUT"] = "ON"
        tc.variables['CMAKE_EXPORT_COMPILE_COMMANDS'] = 'ON'
        tc.variables["CTEST_OUTPUT_ON_FAILURE"] = "ON"
        tc.variables["MEMORY_SANITIZER_ON"] = "OFF"
        tc.variables["BUILD_COVERAGE"] = "OFF"
        if self.settings.build_type == "Debug":
            if self.options.get_safe("coverage"):
                tc.variables['BUILD_COVERAGE'] = 'ON'
            elif self.options.get_safe("sanitize"):
                tc.variables['MEMORY_SANITIZER_ON'] = 'ON'
        tc.generate()

        # This generates "boost-config.cmake" and "grpc-config.cmake" etc in self.generators_folder
        deps = CMakeDeps(self)
        deps.generate()

    def build(self):
        cmake = CMake(self)
        cmake.configure()
        cmake.build()
        if not self.conf.get("tools.build:skip_test", default=False):
            cmake.test()

    def package(self):
        copy(self, "LICENSE", self.source_folder, join(self.package_folder, "licenses"), keep_path=False)
        copy(self, "*.h", join(self.source_folder, "src", "include"), join(self.package_folder, "include"), keep_path=True)
        copy(self, "*.hpp", join(self.source_folder, "src", "include"), join(self.package_folder, "include"), keep_path=True)
        copy(self, "*.ipp", join(self.source_folder, "src", "include"), join(self.package_folder, "include"), keep_path=True)
        copy(self, "*.a", self.build_folder, join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.so", self.build_folder, join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dylib", self.build_folder, join(self.package_folder, "lib"), keep_path=False)
        copy(self, "*.dll", self.build_folder, join(self.package_folder, "lib"), keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["homestore"]
        if not self.settings.arch in ['x86', 'x86_64']:
            self.cpp_info.defines.append("NO_ISAL")

        if self.options.sanitize:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        if self.settings.os == "Linux":
            self.cpp_info.system_libs.append("aio")
