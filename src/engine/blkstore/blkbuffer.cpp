/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include "blkbuffer.hpp"

namespace homestore {

void intrusive_ptr_add_ref(BlkBuffer* const buf) {
    // manage through base pointer
    intrusive_ptr_add_ref(static_cast< typename BlkBuffer::CacheBufferType* >(buf));
}

void intrusive_ptr_release(BlkBuffer* const buf) {
    // manage through base pointer
    intrusive_ptr_release(static_cast< typename BlkBuffer::CacheBufferType* >(buf));
}

} // namespace homestore
