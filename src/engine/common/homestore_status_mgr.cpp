#include "homestore_status_mgr.hpp"

namespace homestore {
void HomeStoreStatusMgr::register_status_cb(const std::string& module, const get_status_cb_t get_status_cb) {
    std::unique_lock lock(m_mtx);
    m_status_cb_map.emplace(module, get_status_cb);
}

nlohmann::json HomeStoreStatusMgr::get_status(const std::vector< std::string >& modules,
                                              const int verbosity_level) const {
    nlohmann::json status_json;
    std::shared_lock lock(m_mtx);

    if (modules.size() == 0) {
        for (const auto& [module, status_cb] : m_status_cb_map) {
            status_json[module] = status_cb(verbosity_level);
        }
    } else {
        for (const auto& module : modules) {
            const auto module_itr{m_status_cb_map.find(module)};
            if (module_itr != m_status_cb_map.end()) { status_json[module] = module_itr->second(verbosity_level); }
        }
    }
    return status_json;
}

std::vector< std::string > HomeStoreStatusMgr::get_modules() const {
    std::vector< std::string > modules;
    modules.reserve(m_status_cb_map.size());

    std::shared_lock lock(m_mtx);
    for (const auto& module_pair : m_status_cb_map) {
        modules.push_back(module_pair.first);
    }
    return modules;
}

} // namespace homestore
