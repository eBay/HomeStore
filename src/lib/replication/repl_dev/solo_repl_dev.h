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

#include <boost/intrusive_ptr.hpp>

#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include <homestore/logstore/log_store.hpp>
#include <homestore/superblk_handler.hpp>

namespace homestore {
#pragma pack(1)
struct repl_dev_superblk {
    static constexpr uint64_t REPL_DEV_SB_MAGIC = 0xABCDF00D;
    static constexpr uint32_t REPL_DEV_SB_VERSION = 1;

    uint64_t magic{REPL_DEV_SB_MAGIC};
    uint32_t version{REPL_DEV_SB_VERSION};
    uuid_t gid;                    // gid of this replica set
    logstore_id_t data_journal_id; // Logstore id for the data journal
    int64_t commit_lsn;            // LSN upto which this replica has committed
    int64_t checkpoint_lsn;        // LSN upto which this replica have checkpointed the data

#if 0
    logstore_id_t free_pba_store_id; // Logstore id for storing free pba records
#endif

    uint64_t get_magic() const { return magic; }
    uint32_t get_version() const { return version; }
};
#pragma pack()

VENUM(journal_type_t, uint16_t, HS_DATA = 0)
struct repl_journal_entry {
    static constexpr uint16_t JOURNAL_ENTRY_MAJOR = 1;
    static constexpr uint16_t JOURNAL_ENTRY_MINOR = 1;

    // Major and minor version. For each major version underlying structures could change. Minor versions can only add
    // fields, not change any existing fields.
    uint16_t major_version{JOURNAL_ENTRY_MAJOR};
    uint16_t minor_version{JOURNAL_ENTRY_MINOR};

    journal_type_t code;
    uint32_t replica_id;
    uint32_t user_header_size;
    uint32_t key_size;
    // Followed by user_header, then key, then MultiBlkId
};

class CP;

class SoloReplDev : public ReplDev {
private:
    std::shared_ptr< HomeLogStore > m_data_journal;
    superblk< repl_dev_superblk > m_rd_sb;
    uuid_t m_group_id;
    std::atomic< logstore_seq_num_t > m_commit_upto{-1};

public:
    SoloReplDev(superblk< repl_dev_superblk > const& rd_sb, bool load_existing);
    virtual ~SoloReplDev() = default;

    void async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                           intrusive< repl_req_ctx > ctx) override;

    folly::Future< std::error_code > async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                bool part_of_batch = false) override;

    void async_free_blks(int64_t lsn, MultiBlkId const& blkid) override;

    bool is_leader() const override { return true; }

    uuid_t group_id() const override { return m_group_id; }

    void cp_flush(CP* cp);
    void cp_cleanup(CP* cp);

private:
    void on_data_journal_created(shared< HomeLogStore > log_store);
    void write_journal(intrusive< repl_req_ctx > rreq);
    void on_log_found(logstore_seq_num_t lsn, log_buffer buf, void* ctx);
};

} // namespace homestore