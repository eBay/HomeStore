#!/usr/bin/env python
# -*- coding: utf-8 -*-
from conans import ConanFile, CMake, tools

class HomestoreConan(ConanFile):
    name = "homestore"
    version = "0.8.4"

    license = "Proprietary"
    url = "https://github.corp.ebay.com/SDS/Homestore"
    description = "HomeStore"

    settings = "arch", "os", "compiler", "build_type"
    options = {"shared": ['True', 'False'],
               "fPIC": ['True', 'False'],
               "coverage": ['True', 'False']}
    default_options = 'shared=False', 'fPIC=True', 'coverage=False'

    requires = (("benchmark/1.4.1@oss/stable"),
                ("boost_heap/1.66.0@bincrafters/stable"),
                ("boost_uuid/1.66.0@bincrafters/stable"),
                ("double-conversion/3.0.0@bincrafters/stable"),
                ("farmhash/1.0.0@oss/stable"),
                ("folly/2018.08.20.00@bincrafters/stable"),
                ("iomgr/2.0.3@sds/testing"),
                ("sds_metrics/0.2.0@sds/testing"))

    generators = "cmake"
    exports_sources = "cmake/*", "src/*", "CMakeLists.txt"

    def configure(self):
        if not self.settings.compiler == "gcc":
            del self.options.coverage

    def requirements(self):
        if not self.settings.build_type == "Debug":
            self.requires("gperftools/2.7.0@oss/stable")

    def build(self):
        cmake = CMake(self)

        definitions = {'CONAN_BUILD_COVERAGE': 'OFF',
                       'CMAKE_EXPORT_COMPILE_COMMANDS': 'ON'}
        test_target = None

        if self.options.coverage == 'True':
            definitions['CONAN_BUILD_COVERAGE'] = 'ON'
            test_target = 'coverage'

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
        self.cpp_info.libs.extend(["aio"])
        if self.options.coverage == 'True':
            self.cpp_info.libs.append('gcov')
