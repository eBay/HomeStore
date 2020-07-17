#!/usr/bin/env python
# -*- coding: utf-8 -*-
from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"

    version = "0.13.6"
    revision_mode = "scm"

    license = "Proprietary"
    url = "https://github.corp.ebay.com/SDS/Homestore"
    description = "HomeStore"

    settings = "arch", "os", "compiler", "build_type"
    options = {
                "shared": ['True', 'False'],
                "fPIC": ['True', 'False'],
                "coverage": ['True', 'False'],
                "sanitize": ['True', 'False'],
                'malloc_impl' : ['libc', 'tcmalloc', 'jemalloc']
                }
    default_options = (
                        'shared=False',
                        'fPIC=True',
                        'coverage=False',
                        'sanitize=True',
                        'malloc_impl=libc',
                        )

    requires = (
            "flip/0.2.9@sds/develop",
            "iomgr/2.3.0@sds/develop",
            "sds_logging/7.0.2@sds/develop",
            "sisl/1.1.3@sisl/develop",

            # FOSS, rarely updated
            "benchmark/1.5.0",
            "boost/1.73.0",
            "double-conversion/3.1.5",
            "evhtp/1.2.18.2",
            "farmhash/1.0.0",
            "folly/2020.05.04.00",
            "isa-l/2.21.0",
            "libevent/2.1.11",
            "openssl/1.1.1g",
            )

    generators = "cmake"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"
    keep_imports = True

    def configure(self):
        if not self.settings.build_type == "Debug":
            self.options.sanitize = False

        if self.options.sanitize:
            self.options.coverage = False

    def imports(self):
        self.copy(root_package="flip", pattern="*.py", dst="bin/scripts", src="python/flip/", keep_path=True)

    def requirements(self):
        if not self.settings.build_type == "Debug":
            if self.settings.build_type == "RelWithDebInfo":
                self.requires("gperftools/2.7.0")
                self.options.malloc_impl = "tcmalloc"
            else:
                self.requires("jemalloc/5.2.1")
                self.options.malloc_impl = "jemalloc"

    def build(self):
        cmake = CMake(self)

        definitions = {'CONAN_BUILD_COVERAGE': 'OFF',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON',
                       'MEMORY_SANITIZER_ON': 'OFF'}
        test_target = None

        if self.options.sanitize:
            definitions['MEMORY_SANITIZER_ON'] = 'ON'

        if self.options.coverage:
            definitions['CONAN_BUILD_COVERAGE'] = 'ON'
            test_target = 'coverage'

        if self.settings.build_type == 'Debug':
            definitions['CMAKE_BUILD_TYPE'] = 'Debug'

        definitions['MALLOC_IMPL'] = self.options.malloc_impl

        cmake.configure(defs=definitions)
        cmake.build()
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
        if self.settings.build_type != 'Debug':
            self.copy("*test_load", dst="bin", keep_path=False)
            self.copy("*test_mapping", dst="bin", keep_path=False)
            self.copy("*test_volume", dst="bin", keep_path=False)
            self.copy("*check_btree", dst="bin", keep_path=False)
            self.copy("*", dst="bin/scripts", src="bin/scripts", keep_path=True)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
        self.cpp_info.cxxflags.append("-DBOOST_ALLOW_DEPRECATED_HEADERS")
        if self.options.sanitize:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        elif self.options.coverage == 'True':
            self.cpp_info.libs.append('gcov')
        if self.settings.os == "Linux":
            self.cpp_info.libs.extend(["aio"])

    def deploy(self):
        self.copy("*test_load", dst="/usr/local/bin", keep_path=False)
        self.copy("*test_mapping", dst="/usr/local/bin", keep_path=False)
        self.copy("*test_volume", dst="/usr/local/bin", keep_path=False)
        self.copy("*check_btree", dst="/usr/local/bin", keep_path=False)
        self.copy("vol_test.py", dst="/usr/local/bin", src="bin/scripts", keep_path=False)
        self.copy("*", dst="/usr/local/bin/home_blks_scripts", src="bin/scripts", keep_path=True)
