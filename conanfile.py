from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "3.8.4"

    homepage = "https://github.corp.ebay.com/SDS/homestore"
    description = "HomeStore"
    topics = ("ebay", "nublox")
    url = "https://github.corp.ebay.com/SDS/Homestore"
    license = "Proprietary"

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
                'sisl:prerelease': True,
            }


    generators = "cmake", "cmake_find_package"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt", "test_wrap.sh"
    keep_imports = True

    def configure(self):
        if self.options.shared:
            del self.options.fPIC
        if self.settings.build_type == "Debug":
            if self.options.coverage and self.options.sanitize:
                raise ConanInvalidConfiguration("Sanitizer does not work with Code Coverage!")
            if self.options.sanitize:
                self.options['sisl'].malloc_impl = 'libc'
            elif self.options.coverage:
                self.options.testing = 'min'

    def imports(self):
        self.copy(root_package="sisl", pattern="*", dst="bin/scripts/python/flip/", src="bindings/flip/python/", keep_path=False)

    def build_requirements(self):
        self.build_requires("benchmark/1.7.1")
        self.build_requires("gtest/1.12.1")

    def requirements(self):
        self.requires("iomgr/[^8.8]")
        self.requires("sisl/[~=8]")

        # FOSS, rarely updated
        self.requires("boost/1.79.0")
        self.requires("farmhash/cci.20190513@")
        self.requires("folly/2022.01.31.00")
        self.requires("isa-l/2.30.0")
        self.requires("nlohmann_json/3.11.2")

    def build(self):
        cmake = CMake(self)

        definitions = {'TEST_TARGET': 'off',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON',
                       'CONAN_CMAKE_SILENT_OUTPUT': 'ON',
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
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.hpp", dst="include", src="src", keep_path=True)
        self.copy("*/btree_node.cpp", dst="include", src="src", keep_path=True)
        self.copy("*cache/cache.ipp", dst="include", src="src", keep_path=True)
        self.copy("*homeblks.so", dst="lib", keep_path=False)
        self.copy("*homeblks.dll", dst="lib", keep_path=False)
        self.copy("*homeblks.dylib", dst="lib", keep_path=False)
        self.copy("*homeblks.lib", dst="lib", keep_path=False)
        self.copy("*homeblks.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = ["homeblks"]
        if self.options.sanitize:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        if self.settings.os == "Linux":
            self.cpp_info.system_libs.append("aio")
