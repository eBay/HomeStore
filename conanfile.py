#!/usr/bin/env python
# -*- coding: utf-8 -*-
from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"

    version = "0.11.3"

    license = "Proprietary"
    url = "https://github.corp.ebay.com/SDS/Homestore"
    description = "HomeStore"

    settings = "arch", "os", "compiler", "build_type", "sanitize"
    options = {"shared": ['True', 'False'],
               "fPIC": ['True', 'False'],
               "coverage": ['True', 'False']}
    default_options = 'shared=False', 'fPIC=True', 'coverage=False'

    requires = (
                "benchmark/1.4.1@oss/stable",
                "boost_dynamic_bitset/1.67.0@bincrafters/stable",
                "boost_heap/1.67.0@bincrafters/stable",
                "boost_uuid/1.67.0@bincrafters/stable",
                "double-conversion/3.1.1@bincrafters/stable",
                "farmhash/1.0.0@oss/stable",
                "folly/2018.12.10.00@bincrafters/testing",
                "gtest/1.8.1@bincrafters/stable",
                "iomgr/2.1.1@sds/testing",
                "lzma/5.2.4@bincrafters/stable",
                "sisl/0.2.1@sisl/testing",
                "OpenSSL/1.0.2q@conan/stable",
                "sds_logging/3.8.1@sds/testing",
                "sds_options/0.1.4@sds/testing",
                "isa-l/2.21.0@oss/stable",
                )

    generators = "cmake"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"

    def configure(self):
        if self.settings.sanitize != None:
            del self.options.coverage

    def requirements(self):
        if not self.settings.build_type == "Debug":
            self.requires("gperftools/2.7.0@oss/stable")

    def build(self):
        cmake = CMake(self)

        definitions = {'CONAN_BUILD_COVERAGE': 'OFF',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON',
                       'MEMORY_SANITIZER_ON': 'OFF'}
        test_target = None

        if self.settings.sanitize != "address" and self.options.coverage == 'True':
            definitions['CONAN_BUILD_COVERAGE'] = 'ON'
            test_target = 'coverage'

        if self.settings.sanitize != None:
            definitions['MEMORY_SANITIZER_ON'] = 'ON'

        cmake.configure(defs=definitions)
        cmake.build()
        cmake.test(target=test_target)

    def package(self):
        self.copy("*.h", dst="include", src="src", keep_path=True)
        self.copy("*.hpp", dst="include", src="src", keep_path=True)
        self.copy("*/btree_node.cpp", dst="include", src="src", keep_path=True)
        self.copy("*cache/cache.cpp", dst="include", src="src", keep_path=True)
        self.copy("*.so", dst="lib", keep_path=False)
        self.copy("*.dll", dst="lib", keep_path=False)
        self.copy("*.dylib", dst="lib", keep_path=False)
        self.copy("*.lib", dst="lib", keep_path=False)
        self.copy("*.a", dst="lib", keep_path=False)

    def package_info(self):
        self.cpp_info.libs = tools.collect_libs(self)
        if self.settings.sanitize != None:
            self.cpp_info.sharedlinkflags.append("-fsanitize=address")
            self.cpp_info.exelinkflags.append("-fsanitize=address")
            self.cpp_info.sharedlinkflags.append("-fsanitize=undefined")
            self.cpp_info.exelinkflags.append("-fsanitize=undefined")
        elif self.options.coverage == 'True':
            self.cpp_info.libs.append('gcov')
        if self.settings.os == "Linux":
            self.cpp_info.libs.extend(["aio"])
