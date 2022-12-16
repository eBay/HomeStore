/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Rishabh Mittal, Yaming Kuang
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
#include <sisl/logging/logging.h>

namespace homestore {

class Snapshot {
private:
    uint64_t m_snapId;
    uint64_t m_seqId;
    boost::uuids::uuid m_uuid;

    Volume* m_volume;

public:
    Snapshot(Volume* vol, uint64_t snapId, uint64_t seqId) : m_snapId(snapId), m_seqId(seqId), m_volume(vol){};

    ~Snapshot(){};

    std::string to_string() {
        std::stringstream ss;
        ss << "Snapshot: snapId:" << m_snapId << ", SeqId:" << m_seqId << ", Volume[" << m_volume << "]";
        return ss.str();
    }
};

typedef std::shared_ptr< Snapshot > SnapshotPtr;
} // namespace homestore
