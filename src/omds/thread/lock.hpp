/*
 * lock.hpp
 *
 *  Created on: 21-Feb-2017
 *      Author: hkadayam
 */

#ifndef THREAD_LOCK_HPP_
#define THREAD_LOCK_HPP_

namespace omds { namespace thread {

class RWLock
{
public:
	RWLock()
	{
		pthread_rwlock_init(&m_lock, NULL);
	}

	~RWLock()
	{
		pthread_rwlock_destroy(&m_lock);
	}

	void read_lock()
	{
		pthread_rwlock_rdlock(&m_lock);
	}

	void write_lock()
	{
		pthread_rwlock_wrlock(&m_lock);
	}

	void unlock()
	{
		pthread_rwlock_unlock(&m_lock);
	}

private:
	pthread_rwlock_t m_lock;
};

enum locktype_t {
	LOCK_NONE=0,
	LOCK_READ,
	LOCK_WRITE
};

} }

#endif /* THREAD_LOCK_HPP_ */
