/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Author/Developer(s): Harihara Kadayam
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
#include "homeds/memory/obj_allocator.hpp"
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
RCU_REGISTER_INIT

using namespace homeds;
using namespace std;

template < typename T >
class Node {
public:
    Node(T id) { m_id = id; }

    T get_id() { return m_id; }

    ~Node() { std::cout << "Destructor of Node " << m_id << " called\n"; }

private:
    T m_id;
};

int main(int argc, char** argv) {
    Node< uint64_t >* ptr1 = homeds::ObjectAllocator< Node< uint64_t > >::make_object((uint64_t)-1);
    std::cout << "ptr1 = " << (void*)ptr1 << " Id = " << ptr1->get_id() << std::endl;
    homeds::ObjectAllocator< Node< uint64_t > >::deallocate(ptr1);
}
