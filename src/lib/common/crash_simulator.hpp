#pragma once

#ifdef _PRERELEASE
#include <functional>
#include <sisl/utility/urcu_helper.hpp>
#include <iomgr/iomgr_flip.hpp>

namespace homestore {

class CrashSimulator {
public:
    CrashSimulator(std::function< void(void) > cb = nullptr) : m_restart_cb{cb} {}
    ~CrashSimulator() = default;

    void crash() {
        if (m_restart_cb) {
            m_crashed.update([](auto* s) { *s = true; });

            // We can restart on a new thread to allow other operations to continue
            std::thread t([this]() { m_restart_cb(); });
            t.detach();
        } else {
            raise(SIGKILL);
        }
    }

    bool is_crashed() const { return ((m_restart_cb != nullptr) && *(m_crashed.access().get())); }

    bool crash_if_flip_set(const std::string& flip_name) {
        if (iomgr_flip::instance()->test_flip(flip_name)) {
            this->crash();
            return true;
        } else {
            return false;
        }
    }

private:
    std::function< void(void) > m_restart_cb{nullptr};
    sisl::urcu_scoped_ptr< bool > m_crashed;
};
} // namespace homestore
#endif
