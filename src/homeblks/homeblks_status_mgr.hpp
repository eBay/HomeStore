#pragma once

#include <string>
#include <functional>
#include <unordered_map>
#include <vector>

#include <nlohmann/json.hpp>


namespace homestore {

using get_status_cb_t = std::function< nlohmann::json(const int verbosity_level) >;

class HomeBlksStatusMgr {
public:
    HomeBlksStatusMgr() = default;

    void register_status_cb(const std::string module, const get_status_cb_t get_status_cb);
    nlohmann::json get_status (const std::vector<std::string>& modules, const int verbosity_level) const;
    void get_modules(std::vector<std::string>& modules);

private:
    std::unordered_map< std::string, get_status_cb_t > m_status_cb_map;


};

} // namespace homestore