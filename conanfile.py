from os.path import join
from conan import ConanFile
from conan.tools.files import copy
from conans import CMake

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "5.1.12"

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
                "skip_testing": ['True', 'False'],
            }
    default_options = {
                'shared': False,
                'fPIC': True,
                'coverage': False,
                'sanitize': False,
                'testing': 'epoll_mode',
                'skip_testing': False,
            }


    generators = "cmake", "cmake_find_package"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt", "test_wrap.sh", "LICENSE"
    keep_imports = True

    def configure(self):
        if self.options.shared:
            del self.options.fPIC
        if self.settings.build_type == "Debug":
            if self.options.coverage and self.options.sanitize:
                raise ConanInvalidConfiguration("Sanitizer does not work with Code Coverage!")
            if self.options.testing == 'off':
                if self.options.coverage or self.options.sanitize:
                    raise ConanInvalidConfiguration("Coverage/Sanitizer requires Testing!")

    def imports(self):
        self.copy(root_package="sisl", pattern="*", dst="bin/scripts/python/flip/", src="bindings/flip/python/", keep_path=False)

    def build_requirements(self):
        self.build_requires("benchmark/1.8.2")
        self.build_requires("gtest/1.14.0")

    def requirements(self):
        self.requires("iomgr/[~=11, include_prerelease=True]@oss/master")
        self.requires("sisl/[~=11, include_prerelease=True]@oss/master")
        self.requires("nuraft_mesg/[~=3, include_prerelease=True]@oss/main")

        self.requires("farmhash/cci.20190513@")
        if self.settings.arch in ['x86', 'x86_64']:
            self.requires("isa-l/2.30.0")
        self.requires("spdk/21.07.y")

    def build(self):
        cmake = CMake(self)

        definitions = {'TEST_TARGET': 'off',
                       'CONAN_CMAKE_SILENT_OUTPUT': 'ON',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON',
                       'MEMORY_SANITIZER_ON': 'OFF'}
        test_target = None

        definitions['TEST_TARGET'] = self.options.testing
        if self.settings.build_type == 'Debug':
            if self.options.sanitize:
                definitions['MEMORY_SANITIZER_ON'] = 'ON'
            elif self.options.coverage:
                definitions['CONAN_BUILD_COVERAGE'] = 'ON'
        cmake.configure(defs=definitions)
        cmake.build()
        if not self.options.testing == 'off' and not self.options.skip_testing:
            cmake.test(target=test_target, output_on_failure=True)

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
        if self.options.sanitize:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        if self.settings.os == "Linux":
            self.cpp_info.system_libs.append("aio")
