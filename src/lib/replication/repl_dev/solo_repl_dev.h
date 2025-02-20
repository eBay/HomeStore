/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#pragma once

#include <boost/smart_ptr/intrusive_ref_counter.hpp>
#include <boost/intrusive_ptr.hpp>

#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include <homestore/logstore/log_store.hpp>
#include <homestore/superblk_handler.hpp>

#include "replication/repl_dev/common.h"

namespace homestore {
class CP;

class SoloReplDev : public ReplDev {
private:
    logdev_id_t m_logdev_id;
    std::shared_ptr< HomeLogStore > m_data_journal;
    superblk< repl_dev_superblk > m_rd_sb;
    uuid_t m_group_id;
    std::atomic< logstore_seq_num_t > m_commit_upto{-1};

public:
    SoloReplDev(superblk< repl_dev_superblk >&& rd_sb, bool load_existing);
    virtual ~SoloReplDev() = default;

    // TODO: implement graceful shutdown for solo repl dev

    void async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                           repl_req_ptr_t ctx) override;

    folly::Future< std::error_code > async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false) override;

    folly::Future< std::error_code > async_free_blks(int64_t lsn, MultiBlkId const& blkid) override;

    AsyncReplResult<> become_leader() override { return make_async_error(ReplServiceError::OK); }
    bool is_leader() const override { return true; }
    replica_id_t get_leader_id() const override { return m_group_id; }
    std::vector< peer_info > get_replication_status() const override {
        return std::vector< peer_info >{peer_info{.id_ = m_group_id, .replication_idx_ = 0, .last_succ_resp_us_ = 0}};
    }
    bool is_ready_for_traffic() const override { return true; }
    void purge() override {}

    std::shared_ptr<snapshot_context> deserialize_snapshot_context(sisl::io_blob_safe &snp_ctx) override {
        return nullptr;
    }

    uuid_t group_id() const override { return m_group_id; }

    repl_lsn_t get_last_commit_lsn() const override { return 0; }

    uint32_t get_blk_size() const override;

    void cp_flush(CP* cp);
    void cp_cleanup(CP* cp);

private:
    void write_journal(repl_req_ptr_t rreq);
    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx);
};

} // namespace homestore
