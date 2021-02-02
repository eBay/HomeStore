#pragma once
#ifdef _PRERELEASE
#include <flip/flip.hpp>
#include <iomgr/iomgr.hpp>
#include <functional>
#include <memory>

namespace homestore {
class FlipTimerIOMgr : public flip::FlipTimerBase {
public:
    void schedule(boost::posix_time::time_duration delay_us, const std::function< void() >& closure) override {
        auto cb = [closure]([[maybe_unused]] void* cookie) { closure(); };
        iomgr::IOManager::instance().schedule_thread_timer(delay_us.total_nanoseconds(), false /* recurring */,
                                                           nullptr /* cookie */, cb);
    }
};

class HomeStoreFlip : public flip::Flip {
public:
    static HomeStoreFlip* instance() {
        static HomeStoreFlip inst;
        return &inst;
    }

    static flip::FlipClient* client_instance() {
        static flip::FlipClient fc(HomeStoreFlip::instance());
        return &fc;
    }

    HomeStoreFlip() : flip::Flip() {
        override_timer((std::unique_ptr< flip::FlipTimerBase >(std::make_unique< homestore::FlipTimerIOMgr >())));
    }

    /**
     * @brief : test flip and abort without core dump
     *
     * @param flip_name :
     */
    void test_and_abort(const std::string& flip_name) {
        if (test_flip(flip_name.c_str())) {
            // abort without generating core dump
            raise(SIGKILL);
        }
    }
};

#define homestore_flip HomeStoreFlip::instance()
} // namespace homestore
#endif
