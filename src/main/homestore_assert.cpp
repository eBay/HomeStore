#include "homestore_assert.hpp"
#include <metrics/metrics.hpp>

namespace homestore {
template < typename... Args >
void hs_cmp_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str,
                             const Args&... args) {
    sds_logging::default_cmp_assert_formatter(buf, msg, args...);
    hs_assert_formatter(buf, msg, req_str, args...);
}

template < typename... Args >
void hs_assert_formatter(fmt::memory_buffer& buf, const char* msg, const std::string& req_str, const Args&... args) {
    if (req_str.size()) {
        fmt::format_to(buf, "\n[request={}]", req_str);
    }
    fmt::format_to(buf, "\nMetrics = {}\n", sisl::MetricsFarm::getInstance().get_result_in_json_string());
}
} // namespace homestore