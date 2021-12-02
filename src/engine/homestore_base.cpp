#include <sisl/fds/buffer.hpp>
#include <iomgr/iomgr.hpp>

#include "homestore_base.hpp"
#include "common/homestore_status_mgr.hpp"
#include "common/homestore_assert.hpp"

namespace homestore {
HomeStoreBase::~HomeStoreBase() = default;

void HomeStoreBase::set_instance(HomeStoreBaseSafePtr instance) { s_instance = instance; }

void HomeStoreBase::reset_instance() { s_instance.reset(); }

std::shared_ptr< spdlog::logger >& HomeStoreBase::periodic_logger() { return instance()->m_periodic_logger; }

HomeStoreStatusMgr* HomeStoreBase::status_mgr() { return m_status_mgr.get(); }
} // namespace homestore
