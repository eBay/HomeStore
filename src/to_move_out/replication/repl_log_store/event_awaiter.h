/**
 * Copyright (C) 2017-present Jung-Sang Ahn <jungsang.ahn@gmail.com>
 * All rights reserved.
 *
 * https://github.com/greensky00
 *
 * Event Awaiter
 * Version: 0.1.1
 *
 * Permission is hereby granted, free of charge, to any person
 * obtaining a copy of this software and associated documentation
 * files (the "Software"), to deal in the Software without
 * restriction, including without limitation the rights to use,
 * copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following
 * conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
 * OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT
 * HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
 * WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
 * OTHER DEALINGS IN THE SOFTWARE.
 */

#pragma once

#include <atomic>
#include <condition_variable>
#include <cstdlib>
#include <memory>
#include <mutex>

class EventAwaiter {
private:
    enum class AS { idle = 0x0, ready = 0x1, waiting = 0x2, done = 0x3 };

public:
    EventAwaiter() : status(AS::idle) {}

    void reset() { status.store(AS::idle); }

    void wait() { wait_us(0); }

    void wait_ms(size_t time_ms) { wait_us(time_ms * 1000); }

    void wait_us(size_t time_us) {
        AS expected = AS::idle;
        if (status.compare_exchange_strong(expected, AS::ready)) {
            // invoke() has not been invoked yet, wait for it.
            std::unique_lock< std::mutex > l(cvLock);
            expected = AS::ready;
            if (status.compare_exchange_strong(expected, AS::waiting)) {
                if (time_us) {
                    cv.wait_for(l, std::chrono::microseconds(time_us));
                } else {
                    cv.wait(l);
                }
                status.store(AS::done);
            } else {
                // invoke() has grabbed `cvLock` earlier than this.
            }
        } else {
            // invoke() already has been called earlier than this.
        }
    }

    void invoke() {
        AS expected = AS::idle;
        if (status.compare_exchange_strong(expected, AS::done)) {
            // wait() has not been invoked yet, do nothing.
            return;
        }

        std::unique_lock< std::mutex > l(cvLock);
        expected = AS::ready;
        if (status.compare_exchange_strong(expected, AS::done)) {
            // wait() has been called earlier than invoke(),
            // but invoke() has grabbed `cvLock` earlier than wait().
            // Do nothing.
        } else {
            // wait() is waiting for ack.
            cv.notify_all();
        }
    }

private:
    std::atomic< AS > status;
    std::mutex cvLock;
    std::condition_variable cv;
};
