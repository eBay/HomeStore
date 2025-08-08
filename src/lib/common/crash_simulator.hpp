#pragma once

#ifdef _PRERELEASE
#include <functional>
#include <sisl/utility/urcu_helper.hpp>
#include <iomgr/iomgr_flip.hpp>

namespace homestore {

class CrashSimulator {
public:
    CrashSimulator(std::function< void(void) > cb = nullptr) : m_restart_cb{std::move(cb)} {}
    ~CrashSimulator() = default;

    void crash_now() {
        if (m_restart_cb) {
            m_crashed.update([](auto* s) { *s = true; });

            // We can restart on a new thread to allow other operations to continue
            std::thread t([cb = std::move(m_restart_cb)]() {
                // Restart could destroy this pointer, so we are storing in local variable and then calling.
                cb();
            });
            t.detach();
        } else {
            raise(SIGKILL);
        }
    }

    void start_crash() {
        m_crashed.update([](auto* s) { *s = true; });
    }

    bool is_in_crashing_phase() const { return *(m_crashed.access().get()); }

    bool crash_if_flip_set(const std::string& flip_name) {
        if (iomgr_flip::instance()->test_flip(flip_name)) {
            this->crash_now();
            return true;
        } else {
            return false;
        }
    }

    bool will_crash() const { return m_will_crash.load(); }
    void set_will_crash(bool crash) { m_will_crash.store(crash); }

private:
    std::function< void(void) > m_restart_cb{nullptr};
    std::atomic<bool> m_will_crash{false};
    sisl::urcu_scoped_ptr< bool > m_crashed;
};
} // namespace homestore
#endif
