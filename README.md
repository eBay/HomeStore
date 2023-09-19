# HomeStore
[![Conan Build](https://github.com/eBay/HomeStore/actions/workflows/merge_build.yml/badge.svg?branch=master)](https://github.com/eBay/HomeStore/actions/workflows/merge_build.yml)
[![CodeCov](https://codecov.io/gh/eBay/homestore/branch/master/graph/badge.svg)](https://codecov.io/gh/eBay/homestore)

Homestore is a generic *StorageEngine* upon which different *StorageSolution*s can be built. These Solutions can model
Block, K/V, Object or Database *StorageInterface*s.

The architecture is tuned towards modern storage devices and systems programming leveraging the "run to complete" model
provide by [IOManager](https://github.com/eBay/IOManager) to provide maximum performance. Homestore has a pluggable
model throughout making it easy to extend the functionality to tune to specific use cases or data patterns.

A reference Object *StorageSolution* can be found in [HomeObject](https://github.com/eBay/HomeObject).

## Building Blocks
Several building blocks are provided by Homestore that should satisfy the majority cases for custom any given storage
solution. Each "service" provides a crash-resilient and persistent form of familiar data structures.

### MetaSvc (Map)
// TODO

### DataSvc (Heap)
// TODO

### IndexSvc (HashMap)
// TODO

### LogSvc (Circular Buffer)
// TODO

## Building

### System Pre-requisites
* CMake 3.13 or later
* conan 1.x (`pipx install conan~=1`)
* libaio-dev (assuming Ubuntu)
* uuid-dev (assuming Ubuntu)

### Dependencies
* SISL
```
$ git clone https://github.com/eBay/sisl
$ cd sisl & ./prepare.sh && conan export . oss/master
```

* IOManager
```
$ git clone https://github.com/eBay/iomanager
$ cd iomanager & ./prepare.sh && conan export . oss/master
```

### Compilation
```
$ mkdir build
$ cd build

# Install all dependencies
$ conan install ..

# if it is the first time for building and some errors happens when installing dependencies,
# please try to build all dependencies by yourself
$ conan install -u -b missing ..

# Build the libhomestore.a
$ conan build ..
```

## Contributing to This Project
We welcome contributions. If you find any bugs, potential flaws and edge cases, improvements, new feature suggestions or
discussions, please submit issues or pull requests.

Contact
Harihara Kadayam hkadayam@ebay.com

## License Information
Copyright 2021 eBay Inc.

Primary Author: Harihara Kadayam
Primary Developers: Harihara Kadayam, Rishabh Mittal, Yaming Kuang, Brian Szmyd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the
License. You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an
"AS IS" BASIS, WITHOUT WARRANTIES OR CONDITHomeStore OF ANY KIND, either express or implied. See the License for the
specific language governing permissions and limitations under the License.
