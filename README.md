# HomeStore
[![Conan Build](https://github.com/eBay/HomeStore/actions/workflows/merge_conan_build.yml/badge.svg?branch=master)](https://github.com/eBay/HomeStore/actions/workflows/merge_conan_build.yml)

Homestore is a generic storage engine upon which different storage solutions, like block store, key/value stores, object stores, databases can be built. This storage engine architecture is tuned towards modern storage devices and systems programming to provide ultra high performance. It has a pluggable model throughout to make it easy to extend the functionality to tune to specific use cases or data patterns. This document tries to explain what is the motivation to create another storage engine among an already impressive array of engines.

More details to follow....

## Building

### prerequires
```
camke 3.13 or later
conan 1.5x.0 (pip install --user conan==1.59.0)
libjemalloc-dev
libaio-dev
uuid-dev
```
Assuming the conan setup is already done
### build
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
We welcome contributions. If you find any bugs, potential flaws and edge cases, improvements, new feature suggestions or discussions, please submit issues or pull requests.

Contact
Harihara Kadayam hkadayam@ebay.com

## License Information
Copyright 2021 eBay Inc.

Primary Author: Harihara Kadayam

Primary Developers: Harihara Kadayam, Rishabh Mittal, Yaming Kuang, Brian Szmyd

Licensed under the Apache License, Version 2.0 (the "License"); you may not use this file except in compliance with the License. You may obtain a copy of the License at https://www.apache.org/licenses/LICENSE-2.0.

Unless required by applicable law or agreed to in writing, software distributed under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR CONDITHomeStore OF ANY KIND, either express or implied. See the License for the specific language governing permissions and limitations under the License.
