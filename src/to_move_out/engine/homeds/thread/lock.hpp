/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
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
#ifndef THREAD_LOCK_HPP_
#define THREAD_LOCK_HPP_

#include <pthread.h>

namespace homeds {
namespace thread {

class RWLock {
public:
    RWLock() { pthread_rwlock_init(&m_lock, NULL); }

    ~RWLock() { pthread_rwlock_destroy(&m_lock); }

    void read_lock() { pthread_rwlock_rdlock(&m_lock); }

    void write_lock() { pthread_rwlock_wrlock(&m_lock); }

    void unlock() { pthread_rwlock_unlock(&m_lock); }

private:
    pthread_rwlock_t m_lock;
};

enum locktype { LOCKTYPE_NONE = 0, LOCKTYPE_READ, LOCKTYPE_WRITE };

} // namespace thread
} // namespace homeds

#endif /* THREAD_LOCK_HPP_ */
