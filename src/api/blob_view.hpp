/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
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
#pragma once

/* NOTE: This file must stay dependency-free (only <memory> and sisl::blob) so it can be
 * included both from public interface headers (e.g. vol_interface.hpp, which must avoid
 * including homestore-internal headers) and from internal engine headers.
 */

#include <memory>

#include <sisl/fds/buffer.hpp>

namespace homestore {

/* A sisl::blob that also carries a type-erased ownership token. As long as a blob_view
 * instance is alive, m_holder keeps whatever backing memory blob.bytes points into alive too
 * (whatever that memory actually is is opaque here on purpose). Callers should bind the
 * result of an at_offset()-style accessor to `auto` so this token is not sliced away. */
struct blob_view : public sisl::blob {
    std::shared_ptr< void > m_holder;
};

} // namespace homestore
