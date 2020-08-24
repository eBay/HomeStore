#!/usr/bin/env python
# -*- coding: utf-8 -*-
from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"

    version = "0.14.0"
    revision_mode = "scm"

    license = "Proprietary"
    url = "https://github.corp.ebay.com/SDS/Homestore"
    description = "HomeStore"

    settings = "arch", "os", "compiler", "build_type"
    options = {
                "shared": ['True', 'False'],
                "fPIC": ['True', 'False'],
                "sanitize": ['True', 'False'],
                'malloc_impl' : ['libc', 'jemalloc'],
                'testing' : ['coverage', 'full', 'min', 'off'],
                }
    default_options = (
                        'shared=False',
                        'fPIC=True',
                        'sanitize=True',
                        'malloc_impl=libc',
                        'testing=full',
                        )

    requires = (
            "flip/[~=0, include_prerelease=True]@sds/master",
            "iomgr/[~=3, include_prerelease=True]@sds/master",
            "sds_logging/[~=7, include_prerelease=True]@sds/master",
            "sisl/[~=3, include_prerelease=True]@sisl/master",

            # FOSS, rarely updated
            "benchmark/1.5.0",
            "boost/1.73.0",
            "double-conversion/3.1.5",
            "evhtp/1.2.18.2",
            "farmhash/1.0.0",
            "folly/2020.05.04.00",
            "isa-l/2.21.0",
            "libevent/2.1.11",
            "openssl/1.1.1g"
            )

    generators = "cmake"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"
    keep_imports = True

    def configure(self):
        if not self.settings.build_type == "Debug":
            self.options.sanitize = False

    def imports(self):
        self.copy(root_package="flip", pattern="*.py", dst="bin/scripts", src="python/flip/", keep_path=True)

    def requirements(self):
        if not self.settings.build_type == "Debug":
            self.requires("jemalloc/5.2.1")
            self.options.malloc_impl = "jemalloc"

    def configure_cmake(self):
        cmake = CMake(self)

        definitions = {'CONAN_TEST_TARGET': 'off',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON',
                       'MEMORY_SANITIZER_ON': 'OFF'}

        if self.options.sanitize:
            definitions['MEMORY_SANITIZER_ON'] = 'ON'

        if self.options.coverage:
            definitions['CONAN_BUILD_COVERAGE'] = 'ON'
            
        definitions['CONAN_TEST_TARGET'] = self.options.testing

        if self.settings.build_type == 'Debug':
            definitions['CMAKE_BUILD_TYPE'] = 'Debug'

        definitions['MALLOC_IMPL'] = self.options.malloc_impl

        cmake.configure(defs=definitions)
        return cmake

    def build(self):
        cmake = self.configure_cmake()
        cmake.build()
        
        test_target = None
        if self.options.testing == 'coverage':
            test_target = 'coverage'

        if not self.options.testing == 'off':
            cmake.test(target=test_target, output_on_failure=True)

    def package(self):
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.hpp", dst="include", src="src", keep_path=True)
        self.copy("*/btree_node.cpp", dst="include", src="src", keep_path=True)
        self.copy("*cache/cache.cpp", dst="include", src="src", keep_path=True)
        self.copy("*homeblks.so", dst="lib", keep_path=False)
        self.copy("*homeblks.dll", dst="lib", keep_path=False)
        self.copy("*homeblks.dylib", dst="lib", keep_path=False)
        self.copy("*homeblks.lib", dst="lib", keep_path=False)
        self.copy("*homeblks.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
        self.cpp_info.cxxflags.append("-DBOOST_ALLOW_DEPRECATED_HEADERS")
        if self.options.sanitize:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        elif self.options.testing == 'coverage':
            self.cpp_info.libs.append('gcov')
        if self.settings.os == "Linux":
            self.cpp_info.libs.extend(["aio"])
