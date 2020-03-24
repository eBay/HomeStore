/*
 * lock.hpp
 *
 *  Created on: 21-Feb-2017
 *      Author: hkadayam
 */

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
