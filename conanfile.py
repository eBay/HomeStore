#!/usr/bin/env python
# -*- coding: utf-8 -*-
from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "3.2.23"

    revision_mode = "scm"
    license = "Proprietary"
    url = "https://github.corp.ebay.com/SDS/Homestore"
    description = "HomeStore"

    settings = "arch", "os", "compiler", "build_type"
    options = {
                "shared": ['True', 'False'],
                "fPIC": ['True', 'False'],
                "sanitize": ['True', 'False'],
                'testing' : ['coverage', 'full', 'min', 'off', 'epoll_mode', 'spdk_mode'],
                'prerelease' : ['True', 'False'],
                }
    default_options = (
                        'shared=False',
                        'fPIC=True',
                        'sanitize=True',
                        'testing=spdk_mode',
                        'prerelease=True',
                        )

    build_requires = (
            "benchmark/1.5.0",
            "gtest/1.10.0",
            )
    requires = (
            "flip/[~=3, include_prerelease=True]@sds/master",
            "iomgr/[~=8, include_prerelease=True]@sds/master",
            "sisl/[~=7, include_prerelease=True]@sisl/master",

            # FOSS, rarely updated
            "boost/1.73.0",
            "evhtp/1.2.18.2",
            "farmhash/1.0.0",
            "folly/2020.05.04.00",
            "isa-l/2.21.0",
            )

    generators = "cmake"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt", "test_wrap.sh"
    keep_imports = True

    def configure(self):
        self.options['iomgr'].prerelease = self.options.prerelease
        self.options['flip'].prerelease = self.options.prerelease
        self.options['sisl'].prerelease = self.options.prerelease
        if self.settings.build_type == "Debug":
            if self.options.sanitize:
                self.options['sisl'].malloc_impl = 'libc'
        else:
            self.options.sanitize = False

    def imports(self):
        self.copy(root_package="flip", pattern="*.py", dst="bin/scripts", src="python/flip/", keep_path=True)

    def build(self):
        cmake = CMake(self)

        definitions = {'CONAN_TEST_TARGET': 'off',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON',
                       'MEMORY_SANITIZER_ON': 'OFF'}
        test_target = None

        if self.options.sanitize:
            definitions['MEMORY_SANITIZER_ON'] = 'ON'

        definitions['CONAN_TEST_TARGET'] = self.options.testing
        if self.options.testing == 'coverage':
            test_target = 'coverage'

        if self.settings.build_type == 'Debug':
            definitions['CMAKE_BUILD_TYPE'] = 'Debug'
        
        cmake.configure(defs=definitions)
        cmake.build()
        if not self.options.testing == 'off':
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
        self.cpp_info.libs = tools.collect_libs(self)
        if self.options.sanitize:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        elif self.options.testing == 'coverage':
            self.cpp_info.libs.append('gcov')
        if self.settings.os == "Linux":
            self.cpp_info.libs.extend(["aio"])
