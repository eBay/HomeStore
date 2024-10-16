#pragma once

#ifdef _PRERELEASE
#include <functional>
#include <sisl/utility/urcu_helper.hpp>
#include <iomgr/iomgr_flip.hpp>

namespace homestore {

using RestartCb = std::function< void(bool) >;
class CrashSimulator {
public:
    CrashSimulator(RestartCb cb = nullptr) : m_restart_cb{std::move(cb)} {}
    ~CrashSimulator() = default;

    void crash(bool restart=true) {
        if (m_restart_cb) {
            m_crashed.update([](auto* s) { *s = true; });

            // We can restart on a new thread to allow other operations to continue
            std::thread t([this, restart, cb = m_restart_cb]() {
                // Restart could destroy this pointer, so we are storing in local variable and then calling.
                if(!restart) {
                    LOGINFO("\n\n\n\nWrong call ! crash simulator is not restarting \n\n\n ");
                }
                cb(restart);
                //                if(!restart) {
                //                    LOGINFO("Reset the crash simulator");
                //                    m_crashed.update([](auto* s) { *s = false; });
                //                }
            });
//            if (restart) {
                t.detach();
//            } else {
//
//                t.join();
//                LOGINFO("Reset the crash simulator");
//                m_crashed.update([](auto* s) { *s = false; });
//            }
        } else {
            raise(SIGKILL);
        }
    }

    bool is_crashed() const { return *(m_crashed.access().get()); }
    void proceed() const {
      if (m_restart_cb){
           LOGINFO("Reset the crash simulator");
            m_restart_cb(false);
        }
    }
    bool crash_if_flip_set(const std::string& flip_name) {
        if (iomgr_flip::instance()->test_flip(flip_name)) {
            this->crash();
            return true;
        } else {
            return false;
        }
    }

private:
    RestartCb m_restart_cb{nullptr};
    sisl::urcu_scoped_ptr< bool > m_crashed;
};
} // namespace homestore
#endif
