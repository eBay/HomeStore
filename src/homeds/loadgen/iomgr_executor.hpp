#include <folly/MPMCQueue.h>
#include <iomgr/iomgr.hpp>

namespace homeds {
namespace loadgen {

const size_t num_ep = 2;

class LoadGenEP : public iomgr::EndPoint {
public: 
    LoadGenEP(std::shared_ptr<iomgr::ioMgr> iomgr_ptr) : iomgr::EndPoint(iomgr_ptr) { }
    void shutdown_local() override {}
    void init_local() override {}
    void print_perf() override {}
};

class IOMgrExecutor {
typedef std::function<void()> callback;
public:
    // Create a bounded lock protected queue. 
    IOMgrExecutor(int num_threads, int num_priorities, uint32_t max_queue_size);
    ~IOMgrExecutor();

    // Queues this function to execute in other thread and return back. 
    // If the num_entries in queue > size given in max_queue_size, block and wait until queue becomes less. 
    // IOMgr thread should dequeue the requests and start executing.
    void add(callback done_cb);
    void start();
    void stop();

private:
    void process_ev_callback(const int fd, const void* cookie, const int event);
    bool is_running() const;

private:
    folly::MPMCQueue<callback, std::atomic, true>       m_cq;
    std::shared_ptr<iomgr::ioMgr>                       m_iomgr;
    LoadGenEP*                                          m_ep;
    int                                                 m_ev_fd;
    std::atomic_bool                                    m_running;
};

}
}
