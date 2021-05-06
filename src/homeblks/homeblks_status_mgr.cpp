#include "homeblks_status_mgr.hpp"

namespace homestore {
void HomeBlksStatusMgr::register_status_cb(const std::string module, const get_status_cb_t get_status_cb) {
    m_status_cb_map.emplace(module, get_status_cb);
}

nlohmann::json HomeBlksStatusMgr::get_status(const std::vector< std::string >& modules,
                                             const int verbosity_level) const {
    nlohmann::json status_json;
    for (const auto& module : modules) {
        const auto module_itr{m_status_cb_map.find(module)};
        if (module_itr != m_status_cb_map.end()) { status_json[module] = module_itr->second(verbosity_level); }
    }
    return status_json;
}

void HomeBlksStatusMgr::get_modules(std::vector< std::string >& modules) {
    modules.reserve(m_status_cb_map.size());
    for (const auto& module_pair : m_status_cb_map) {
        modules.push_back(module_pair.first);
    }
}

} // namespace homestore
