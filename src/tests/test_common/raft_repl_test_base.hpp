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

#include <vector>
#include <iostream>
#include <filesystem>
#include <thread>

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>
#include <sisl/fds/buffer.hpp>
#include <folly/init/Init.h>
#include <folly/executors/GlobalExecutor.h>
#include <boost/uuid/nil_generator.hpp>

#include <gtest/gtest.h>
#include <iomgr/iomgr_flip.hpp>
#include <homestore/blk.h>
#include <homestore/homestore.hpp>
#include <homestore/homestore_decl.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/replication_service.hpp>
#include <homestore/replication/repl_dev.h>
#include "common/homestore_config.hpp"
#include "common/homestore_assert.hpp"
#include "common/homestore_utils.hpp"

#define private public
#include "test_common/hs_repl_test_common.hpp"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/raft_repl_dev.h"

using namespace homestore;

SISL_LOGGING_DEF(test_raft_repl_dev)
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS, nuraft_mesg, nuraft)

SISL_OPTION_GROUP(test_raft_repl_dev,
                  (block_size, "", "block_size", "block size to io",
                   ::cxxopts::value< uint32_t >()->default_value("4096"), "number"),
                  (num_raft_groups, "", "num_raft_groups", "number of raft groups per test",
                   ::cxxopts::value< uint32_t >()->default_value("1"), "number"),
                  // for below replication parameter, their default value always get from dynamic config, only used
                  // when specified by user
                  (snapshot_distance, "", "snapshot_distance", "distance between snapshots",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "number"),
                  (num_raft_logs_resv, "", "num_raft_logs_resv", "number of raft logs reserved",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "number"),
                  (res_mgr_audit_timer_ms, "", "res_mgr_audit_timer_ms", "resource manager audit timer",
                   ::cxxopts::value< uint32_t >()->default_value("0"), "number"));

SISL_OPTIONS_ENABLE(logging, test_raft_repl_dev, iomgr, config, test_common_setup, test_repl_common_setup)

static std::unique_ptr< test_common::HSReplTestHelper > g_helper;
static std::random_device g_rd{};
static std::default_random_engine g_re{g_rd()};

class TestReplicatedDB : public homestore::ReplDevListener {
public:
    struct Key {
        uint64_t id_;
        bool operator<(Key const& other) const { return id_ < other.id_; }
    };

    struct Value {
        int64_t lsn_;
        uint64_t data_size_;
        uint64_t data_pattern_;
        MultiBlkId blkid_;
        uint64_t id_;
    };

    struct KeyValuePair {
        Key key;
        Value value;
    };

    struct test_req : public repl_req_ctx {
        struct journal_header {
            uint64_t data_size;
            uint64_t data_pattern;
            uint64_t key_id; // put it in header to test duplication in alloc_local_blks
        };
        journal_header jheader;
        uint64_t key_id;
        sisl::sg_list write_sgs;
        sisl::sg_list read_sgs;

        sisl::blob header_blob() { return sisl::blob(uintptr_cast(&jheader), sizeof(journal_header)); }
        sisl::blob key_blob() { return sisl::blob{uintptr_cast(&key_id), sizeof(uint64_t)}; }

        test_req() {
            write_sgs.size = 0;
            read_sgs.size = 0;
            key_id = (uint64_t)rand() << 32 | rand();
            jheader.key_id = key_id;
        }

        ~test_req() {
            for (auto const& iov : write_sgs.iovs) {
                iomanager.iobuf_free(uintptr_cast(iov.iov_base));
            }

            for (auto const& iov : read_sgs.iovs) {
                iomanager.iobuf_free(uintptr_cast(iov.iov_base));
            }
        }
    };

    TestReplicatedDB() = default;
    virtual ~TestReplicatedDB() = default;

    void on_commit(int64_t lsn, sisl::blob const& header, sisl::blob const& key,
                   std::vector< MultiBlkId > const& blkids, cintrusive< repl_req_ctx >& ctx) override {
        ASSERT_EQ(header.size(), sizeof(test_req::journal_header));
        ASSERT_EQ(blkids.size(), 1);

        auto jheader = r_cast< test_req::journal_header const* >(header.cbytes());
        Key k{.id_ = *(r_cast< uint64_t const* >(key.cbytes()))};
        Value v{.lsn_ = lsn,
                .data_size_ = jheader->data_size,
                .data_pattern_ = jheader->data_pattern,
                .blkid_ = blkids[0],
                .id_ = k.id_};

        LOGINFOMOD(replication, "[Replica={}] Received commit on lsn={} dsn={} key={} value[blkid={} pattern={}]",
                   g_helper->replica_num(), lsn, ctx->dsn(), k.id_, v.blkid_.to_string(), v.data_pattern_);

        {
            std::unique_lock lk(db_mtx_);
            inmem_db_.insert_or_assign(k, v);
            lsn_index_.emplace(lsn, v);
            last_committed_lsn = lsn;
            ++commit_count_;
        }

        if (ctx->is_proposer()) { g_helper->runner().next_task(); }
    }

    bool on_pre_commit(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                       cintrusive< repl_req_ctx >& ctx) override {
        LOGINFOMOD(replication, "[Replica={}] Received pre-commit on lsn={} dsn={}", g_helper->replica_num(), lsn,
                   ctx->dsn());
        return true;
    }

    void on_rollback(int64_t lsn, const sisl::blob& header, const sisl::blob& key,
                     cintrusive< repl_req_ctx >& ctx) override {
        LOGINFOMOD(replication, "[Replica={}] Received rollback on lsn={}", g_helper->replica_num(), lsn);
    }

    void on_restart() {
        LOGINFOMOD(replication, "restarted repl dev for [Replica={}] Group={}", g_helper->replica_num(),
                   boost::uuids::to_string(repl_dev()->group_id()));
    }

    void on_error(ReplServiceError error, const sisl::blob& header, const sisl::blob& key,
                  cintrusive< repl_req_ctx >& ctx) override {
        LOGINFOMOD(replication, "[Replica={}] Received error={} on key={}", g_helper->replica_num(), enum_name(error),
                   *(r_cast< uint64_t const* >(key.cbytes())));
        g_helper->runner().comp_promise_.setException(folly::make_exception_wrapper< ReplServiceError >(error));
    }

    void notify_committed_lsn(int64_t lsn) override {
        LOGINFOMOD(replication, "[Replica={}] Received notify_committed_lsn={}", g_helper->replica_num(), lsn);
    }

    void on_config_rollback(int64_t lsn) override {
        LOGINFOMOD(replication, "[Replica={}] Received config rollback at lsn={}", g_helper->replica_num(), lsn);
    }
    void on_no_space_left(repl_lsn_t lsn, sisl::blob const& header) override {
        LOGINFOMOD(replication, "[Replica={}] Received no_space_left at lsn={}", g_helper->replica_num(), lsn);
    }

    AsyncReplResult<> create_snapshot(shared< snapshot_context > context) override {
        std::lock_guard< std::mutex > lock(m_snapshot_lock);
        auto s = std::dynamic_pointer_cast< nuraft_snapshot_context >(context)->nuraft_snapshot();
        LOGINFOMOD(replication, "[Replica={}] Got snapshot callback term={} idx={}", g_helper->replica_num(),
                   s->get_last_log_term(), s->get_last_log_idx());
        m_last_snapshot = context;
        return make_async_success<>();
    }

    static int64_t get_next_lsn(uint64_t& obj_id) { return obj_id & ((1ULL << 63) - 1); }
    static void set_resync_msg_type_bit(uint64_t& obj_id) { obj_id |= 1ULL << 63; }

    int read_snapshot_obj(shared< snapshot_context > context, shared< snapshot_obj > snp_data) override {
        auto s = std::dynamic_pointer_cast< nuraft_snapshot_context >(context)->nuraft_snapshot();
        if (RaftStateMachine::is_hs_snp_obj(snp_data->offset)) {
            LOGERRORMOD(replication, "invalid snapshot offset={}", snp_data->offset);
            return -1;
        }
        if ((snp_data->offset & snp_obj_id_type_app) == 0) {
            LOGERRORMOD(replication, "invalid snapshot offset={}", snp_data->offset);
            return -1;
        }

        int64_t next_lsn = get_next_lsn(snp_data->offset);
        if (next_lsn == 0) {
            snp_data->is_last_obj = false;
            snp_data->blob = sisl::io_blob_safe(sizeof(ulong));
            LOGINFOMOD(replication,
                       "[Replica={}] Read logical snapshot callback first message obj_id={} term={} idx={}",
                       g_helper->replica_num(), snp_data->offset, s->get_last_log_term(), s->get_last_log_idx());
            return 0;
        }

        std::vector< KeyValuePair > kv_snapshot_obj;
        // we can not use find to get the next element, since if the next lsn is a config lsn , it will not be put into
        // lsn_index_ and as a result, the find will return the end of the map. so here we use lower_bound to get the
        // first element to be read and transfered.
        for (auto iter = lsn_index_.lower_bound(next_lsn); iter != lsn_index_.end(); iter++) {
            auto& v = iter->second;
            kv_snapshot_obj.emplace_back(Key{v.id_}, v);
            LOGTRACEMOD(replication, "[Replica={}] Read logical snapshot callback fetching lsn={} size={} pattern={}",
                        g_helper->replica_num(), v.lsn_, v.data_size_, v.data_pattern_);
            if (kv_snapshot_obj.size() >= 10) { break; }
        }

        if (kv_snapshot_obj.size() == 0) {
            snp_data->is_last_obj = true;
            LOGINFOMOD(replication, "Snapshot is_last_obj is true");
            return 0;
        }

        int64_t kv_snapshot_obj_size = sizeof(KeyValuePair) * kv_snapshot_obj.size();
        sisl::io_blob_safe blob{static_cast< uint32_t >(kv_snapshot_obj_size)};
        std::memcpy(blob.bytes(), kv_snapshot_obj.data(), kv_snapshot_obj_size);
        snp_data->blob = std::move(blob);
        snp_data->is_last_obj = false;
        LOGINFOMOD(replication, "[Replica={}] Read logical snapshot callback obj_id={} term={} idx={} num_items={}",
                   g_helper->replica_num(), snp_data->offset, s->get_last_log_term(), s->get_last_log_idx(),
                   kv_snapshot_obj.size());

        return 0;
    }

    void snapshot_obj_write(uint64_t data_size, uint64_t data_pattern, MultiBlkId& out_blkids) {
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
        auto write_sgs = test_common::HSTestHelper::create_sgs(data_size, block_size, data_pattern);
        auto fut = homestore::data_service().async_alloc_write(write_sgs, blk_alloc_hints{}, out_blkids);
        std::move(fut).get();
        for (auto const& iov : write_sgs.iovs) {
            iomanager.iobuf_free(uintptr_cast(iov.iov_base));
        }
    }

    void write_snapshot_obj(shared< snapshot_context > context, shared< snapshot_obj > snp_data) override {
        if (RaftStateMachine::is_hs_snp_obj(snp_data->offset)) {
            LOGERRORMOD(replication, "invalid snapshot offset={}", snp_data->offset);
            return;
        }
        int64_t next_lsn = get_next_lsn(snp_data->offset);
        auto s = std::dynamic_pointer_cast< nuraft_snapshot_context >(context)->nuraft_snapshot();
        auto last_committed_idx =
            std::dynamic_pointer_cast< RaftReplDev >(repl_dev())->raft_server()->get_committed_log_idx();
        if (next_lsn == 0) {
            snp_data->offset = last_committed_lsn + 1;
            set_resync_msg_type_bit(snp_data->offset);
            LOGINFOMOD(replication, "[Replica={}] Save logical snapshot callback return obj_id={}",
                       g_helper->replica_num(), snp_data->offset);
            return;
        }

        size_t kv_snapshot_obj_size = snp_data->blob.size();
        if (kv_snapshot_obj_size == 0) return;

        size_t num_items = kv_snapshot_obj_size / sizeof(KeyValuePair);
        std::unique_lock lk(db_mtx_);
        auto ptr = r_cast< const KeyValuePair* >(snp_data->blob.bytes());
        for (size_t i = 0; i < num_items; i++) {
            auto key = ptr->key;
            auto value = ptr->value;
            LOGTRACEMOD(replication, "[Replica={}] Save logical snapshot got lsn={} data_size={} data_pattern={}",
                        g_helper->replica_num(), value.lsn_, value.data_size_, value.data_pattern_);

            // Write to data service and inmem map.
            MultiBlkId out_blkids;
            if (value.data_size_ != 0) {
                snapshot_obj_write(value.data_size_, value.data_pattern_, out_blkids);
                value.blkid_ = out_blkids;
            }
            inmem_db_.insert_or_assign(key, value);
            last_committed_lsn = value.lsn_;
            ++commit_count_;
            ptr++;
        }

        snp_data->offset = last_committed_lsn + 1;
        set_resync_msg_type_bit(snp_data->offset);
        LOGINFOMOD(replication,
                   "[Replica={}] Save logical snapshot callback obj_id={} term={} idx={} is_last={} num_items={}",
                   g_helper->replica_num(), snp_data->offset, s->get_last_log_term(), s->get_last_log_idx(),
                   snp_data->is_last_obj, num_items);
    }

    bool apply_snapshot(shared< snapshot_context > context) override {
        std::lock_guard< std::mutex > lock(m_snapshot_lock);
        auto s = std::dynamic_pointer_cast< nuraft_snapshot_context >(context)->nuraft_snapshot();
        LOGINFOMOD(replication, "[Replica={}] Apply snapshot term={} idx={}", g_helper->replica_num(),
                   s->get_last_log_term(), s->get_last_log_idx());
        m_last_snapshot = context;
        return true;
    }

    shared< snapshot_context > last_snapshot() override {
        std::lock_guard< std::mutex > lock(m_snapshot_lock);
        if (!m_last_snapshot) return nullptr;

        auto s = std::dynamic_pointer_cast< nuraft_snapshot_context >(m_last_snapshot)->nuraft_snapshot();
        LOGINFOMOD(replication, "[Replica={}] Last snapshot term={} idx={}", g_helper->replica_num(),
                   s->get_last_log_term(), s->get_last_log_idx());
        return m_last_snapshot;
    }

    void free_user_snp_ctx(void*& user_snp_ctx) override {}

    ReplResult< blk_alloc_hints > get_blk_alloc_hints(sisl::blob const& header, uint32_t data_size,
                                                      cintrusive< homestore::repl_req_ctx >& hs_ctx) override {
        auto jheader = r_cast< test_req::journal_header const* >(header.cbytes());
        Key k{.id_ = jheader->key_id};
        auto iter = inmem_db_.find(k);
        auto hints = blk_alloc_hints{};
        if (iter != inmem_db_.end()) {
            LOGDEBUG("data already exists in mem db, key={}", k.id_);
            hints.committed_blk_id = iter->second.blkid_;
        }
        return hints;
    }

    void on_start_replace_member(const std::string& task_id, const replica_member_info& member_out,
                                 const replica_member_info& member_in, trace_id_t tid) override {
        LOGINFO("[Replica={}] start replace member out {} in {}", g_helper->replica_num(),
                boost::uuids::to_string(member_out.id), boost::uuids::to_string(member_in.id));
    }

    void on_complete_replace_member(const std::string& task_id, const replica_member_info& member_out,
                                    const replica_member_info& member_in, trace_id_t tid) override {
        LOGINFO("[Replica={}] complete replace member out {} in {}", g_helper->replica_num(),
                boost::uuids::to_string(member_out.id), boost::uuids::to_string(member_in.id));
    }

    void on_destroy(const group_id_t& group_id) override {
        LOGINFOMOD(replication, "[Replica={}] Group={} is being destroyed", g_helper->replica_num(),
                   boost::uuids::to_string(group_id));
        g_helper->unregister_listener(group_id);
    }

    void db_write(uint64_t data_size, uint32_t max_size_per_iov) {
        static std::atomic< uint32_t > s_uniq_num{0};
        auto req = intrusive< test_req >(new test_req());
        req->jheader.data_size = data_size;
        req->jheader.data_pattern = ((long long)rand() << 32) | ++s_uniq_num;
        req->jheader.key_id = req->key_id;
        auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();

        LOGINFOMOD(replication, "[Replica={}] Db write key={} data_size={} pattern={} block_size={}",
                   g_helper->replica_num(), req->key_id, data_size, req->jheader.data_pattern, block_size);

        if (data_size != 0) {
            req->write_sgs =
                test_common::HSTestHelper::create_sgs(data_size, max_size_per_iov, req->jheader.data_pattern);
        }

        repl_dev()->async_alloc_write(req->header_blob(), req->key_blob(), req->write_sgs, req, false, s_uniq_num);
    }

    void validate_db_data() {
        g_helper->runner().set_num_tasks(inmem_db_.size());
        while (!repl_dev()->is_ready_for_traffic()) {
            LOGINFO("not yet ready for traffic, waiting");
            std::this_thread::sleep_for(std::chrono::milliseconds{500});
        }

        LOGINFOMOD(replication, "[{}]: Total {} keys committed, validating them",
                   boost::uuids::to_string(repl_dev()->group_id()), inmem_db_.size());
        auto it = inmem_db_.begin();
        g_helper->runner().set_task([this, &it]() {
            Key k;
            Value v;
            {
                std::unique_lock lk(db_mtx_);
                std::tie(k, v) = *it;
                ++it;
            }

            if (v.data_size_ != 0) {
                auto block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
                auto read_sgs = test_common::HSTestHelper::create_sgs(v.data_size_, block_size);

                repl_dev()->async_read(v.blkid_, read_sgs, v.data_size_).thenValue([read_sgs, k, v](auto const ec) {
                    LOGINFOMOD(replication, "Validating key={} value[blkid={} pattern={}]", k.id_, v.blkid_.to_string(),
                               v.data_pattern_);
                    RELEASE_ASSERT(!ec, "Read of blkid={} for key={} error={}", v.blkid_.to_string(), k.id_,
                                   ec.message());
                    for (auto const& iov : read_sgs.iovs) {
                        test_common::HSTestHelper::validate_data_buf(uintptr_cast(iov.iov_base), iov.iov_len,
                                                                     v.data_pattern_);
                        iomanager.iobuf_free(uintptr_cast(iov.iov_base));
                    }
                    g_helper->runner().next_task();
                });
            } else {
                g_helper->runner().next_task();
            }
        });
        g_helper->runner().execute().get();
    }

    uint64_t db_commit_count() const {
        std::shared_lock lk(db_mtx_);
        return commit_count_;
    }

    uint64_t db_size() const {
        std::shared_lock lk(db_mtx_);
        return inmem_db_.size();
    }

    void create_snapshot() {
        auto raft_repl_dev = std::dynamic_pointer_cast< RaftReplDev >(repl_dev());
        ulong snapshot_idx = raft_repl_dev->raft_server()->create_snapshot();
        LOGINFO("Manually create snapshot got index {}", snapshot_idx);
    }

    void truncate(int num_reserved_entries) {
        auto raft_repl_dev = std::dynamic_pointer_cast< RaftReplDev >(repl_dev());
        // raft_repl_dev->truncate(num_reserved_entries);
        LOGINFO("Manually truncated");
    }

    repl_lsn_t get_truncation_upper_limit() {
        auto raft_repl_dev = std::dynamic_pointer_cast< RaftReplDev >(repl_dev());
        auto limit = raft_repl_dev->get_truncation_upper_limit();
        LOGINFO("Truncation upper limit is {}", limit);
        return limit;
    }

    void set_zombie() { zombie_ = true; }
    bool is_zombie() {
        // Wether a group is zombie(non recoverable)
        return zombie_;
    }

private:
    std::map< Key, Value > inmem_db_;
    std::map< int64_t, Value > lsn_index_;
    uint64_t commit_count_{0};
    std::shared_mutex db_mtx_;
    uint64_t last_committed_lsn{0};
    std::shared_ptr< snapshot_context > m_last_snapshot{nullptr};
    std::mutex m_snapshot_lock;
    bool zombie_{false};
};

class RaftReplDevTestBase : public testing::Test {
public:
    void SetUp() override {
        // By default it will create one db
        for (uint32_t i{0}; i < SISL_OPTIONS["num_raft_groups"].as< uint32_t >(); ++i) {
            auto db = std::make_shared< TestReplicatedDB >();
            g_helper->register_listener(db);
            dbs_.emplace_back(std::move(db));
        }
    }

    void TearDown() override {
        for (auto const& db : dbs_) {
            if (db->is_zombie()) { continue; }
            run_on_leader(db, [this, db]() {
                auto err = hs()->repl_service().remove_repl_dev(db->repl_dev()->group_id()).get();
                ASSERT_EQ(err, ReplServiceError::OK) << "Error in destroying the group";
            });
        }

        for (auto const& db : dbs_) {
            if (db->is_zombie()) { continue; }
            auto repl_dev = std::dynamic_pointer_cast< RaftReplDev >(db->repl_dev());
            if (!repl_dev) continue;
            int i = 0;
            bool force_leave = false;
            do {
                std::this_thread::sleep_for(std::chrono::seconds(1));
                auto& raft_repl_svc = dynamic_cast< RaftReplService& >(hs()->repl_service());
                raft_repl_svc.gc_repl_devs();
                LOGINFO("Waiting for repl dev to get destroyed");

                // TODO: if leader is destroyed, but the follower does not receive the notification, it will not be
                // destroyed for ever. we need handle this in raft_repl_dev. revisit here after making changes at
                // raft_repl_dev side to hanle this case. this is a workaround to avoid the infinite loop for now.
                if (i++ > 10 && !force_leave) {
                    LOGWARN("has already waited for repl dev to get destroyed for 10 times, so do a force leave");
                    repl_dev->force_leave();
                    force_leave = true;
                }

            } while (!repl_dev->is_destroyed());
        }
    }

    void generate_writes(uint64_t data_size, uint32_t max_size_per_iov, shared< TestReplicatedDB > db = nullptr) {
        if (db == nullptr) { db = pick_one_db(); }
        // LOGINFO("Writing on group_id={}", db->repl_dev()->group_id());
        db->db_write(data_size, max_size_per_iov);
    }

    void wait_for_all_commits() { wait_for_commits(written_entries_); }

    void wait_for_commits(uint64_t exp_writes) {
        uint64_t total_writes{0};
        while (true) {
            total_writes = 0;
            for (auto const& db : dbs_) {
                total_writes += db->db_commit_count();
            }

            if (total_writes >= exp_writes) { break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(1000));
            LOGINFO("Replica={} received {} commits but expected {}", g_helper->replica_num(), total_writes,
                    exp_writes);
        }
        LOGINFO("Replica={} has received {} commits as expected", g_helper->replica_num(), total_writes);
    }

    void validate_data() {
        for (auto const& db : dbs_) {
            db->validate_db_data();
        }
    }

    shared< TestReplicatedDB > pick_one_db() { return dbs_[0]; }

    void assign_leader(uint16_t replica) {
        LOGINFO("Switch the leader to replica_num = {}", replica);
        if (g_helper->replica_num() == replica) {
            for (auto const& db : dbs_) {
                do {
                    auto result = db->repl_dev()->become_leader().get();
                    if (result.hasError()) {
                        std::this_thread::sleep_for(std::chrono::milliseconds(1000));
                    } else {
                        break;
                    }
                } while (true);
            }
        } else {
            for (auto const& db : dbs_) {
                homestore::replica_id_t leader_uuid;
                while (true) {
                    leader_uuid = db->repl_dev()->get_leader_id();
                    if (!leader_uuid.is_nil() && (g_helper->member_id(leader_uuid) == replica)) { break; }

                    LOGINFO("Waiting for replica={} to become leader", replica);
                    std::this_thread::sleep_for(std::chrono::milliseconds{500});
                }
            }
        }
    }

    void run_on_leader(std::shared_ptr< TestReplicatedDB > db, auto&& lambda) {
        if (!db || !db->repl_dev()) {
            // Spare which are not added to group will not have repl dev.
            return;
        }

        do {
            auto leader_uuid = db->repl_dev()->get_leader_id();

            if (leader_uuid.is_nil()) {
                LOGINFO("Waiting for leader to be elected for group={}", db->repl_dev()->group_id());
                std::this_thread::sleep_for(std::chrono::milliseconds{500});
            } else if (leader_uuid == g_helper->my_replica_id()) {
                lambda();
                break;
            } else {
                break;
            }
        } while (true);
    }

    void write_on_leader(uint32_t num_entries, bool wait_for_commit = true, shared< TestReplicatedDB > db = nullptr,
                         uint64_t* data_size = nullptr) {
        if (dbs_[0]->repl_dev() == nullptr) return;

        do {
            auto repl_dev = dbs_[0]->repl_dev();
            auto leader_uuid = repl_dev->get_leader_id();

            if (leader_uuid.is_nil()) {
                LOGINFO("Waiting for leader to be elected");
                std::this_thread::sleep_for(std::chrono::milliseconds{500});
            } else if (leader_uuid == g_helper->my_replica_id()) {
                LOGINFO("Writing {} entries since I am the leader my_uuid={}", num_entries,
                        boost::uuids::to_string(g_helper->my_replica_id()));
                if (!repl_dev->is_ready_for_traffic()) {
                    LOGINFO("leader is not yet ready for traffic, waiting");
                    std::this_thread::sleep_for(std::chrono::milliseconds{500});
                }
                auto const block_size = SISL_OPTIONS["block_size"].as< uint32_t >();
                g_helper->runner().set_num_tasks(num_entries);

                LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
                g_helper->runner().set_task([this, block_size, db, data_size]() {
                    static std::normal_distribution<> num_blks_gen{3.0, 2.0};
                    uint64_t size =
                        data_size == nullptr ? std::abs(std::lround(num_blks_gen(g_re))) * block_size : *data_size;
                    this->generate_writes(size, block_size, db);
                });
                if (wait_for_commit) { g_helper->runner().execute().get(); }
                break;
            } else {
                LOGINFO("{} entries were written on the leader_uuid={} my_uuid={}", num_entries,
                        boost::uuids::to_string(leader_uuid), boost::uuids::to_string(g_helper->my_replica_id()));
                break;
            }
        } while (true);

        written_entries_ += num_entries;
        if (wait_for_commit) { this->wait_for_all_commits(); }
    }
    replica_id_t wait_and_get_leader_id() {
        do {
            auto leader_uuid = dbs_[0]->repl_dev()->get_leader_id();
            if (leader_uuid.is_nil()) {
                LOGINFO("Waiting for leader to be elected");
                std::this_thread::sleep_for(std::chrono::milliseconds{500});
            } else {
                return leader_uuid;
            }
        } while (true);
    }

    ReplServiceError write_with_id(uint64_t id, bool wait_for_commit = true, shared< TestReplicatedDB > db = nullptr) {
        if (dbs_[0]->repl_dev() == nullptr) return ReplServiceError::FAILED;
        if (db == nullptr) { db = pick_one_db(); }
        LOGINFO("Writing data {} since I am the leader my_uuid={}", id,
                boost::uuids::to_string(g_helper->my_replica_id()));
        auto const block_size = SISL_OPTIONS["block_size"].as< uint32_t >();

        LOGINFO("Run on worker threads to schedule append on repldev for {} Bytes.", block_size);
        g_helper->runner().set_num_tasks(1);
        g_helper->runner().set_task([this, block_size, db, id]() {
            static std::normal_distribution<> num_blks_gen{3.0, 1.0};
            auto data_size = std::max(1L, std::abs(std::lround(num_blks_gen(g_re)))) * block_size;
            ASSERT_GT(data_size, 0);
            LOGINFO("data_size larger than 0, go ahead, data_size= {}.", data_size);
            static std::atomic< uint32_t > s_uniq_num{0};
            auto req = intrusive(new TestReplicatedDB::test_req());
            req->jheader.data_size = data_size;
            req->jheader.data_pattern = ((long long)rand() << 32) | ++s_uniq_num;
            // overwrite the key_id with the id passed in
            req->jheader.key_id = id;
            req->key_id = id;

            LOGINFOMOD(replication, "[Replica={}] Db write key={} data_size={} pattern={} block_size={}",
                       g_helper->replica_num(), req->key_id, data_size, req->jheader.data_pattern, block_size);

            if (data_size != 0) {
                req->write_sgs =
                    test_common::HSTestHelper::create_sgs(data_size, block_size, req->jheader.data_pattern);
            }

            db->repl_dev()->async_alloc_write(req->header_blob(), req->key_blob(), req->write_sgs, req);
        });

        if (!wait_for_commit) { return ReplServiceError::OK; }
        try {
            g_helper->runner().execute().get();
            LOGDEBUG("write data task complete, id={}", id)
        } catch (const ReplServiceError& e) {
            LOGERRORMOD(replication, "[Replica={}] Error in writing data: id={}, error={}", g_helper->replica_num(), id,
                        enum_name(e));
            return e;
        }

        written_entries_ += 1;
        LOGINFO("wait_for_commit={}", written_entries_);
        this->wait_for_all_commits();
        return ReplServiceError::OK;
    }

    void remove_db(std::shared_ptr< TestReplicatedDB > db, bool wait_for_removal) {
        this->run_on_leader(db, [this, db]() {
            auto err = hs()->repl_service().remove_repl_dev(db->repl_dev()->group_id()).get();
            ASSERT_EQ(err, ReplServiceError::OK) << "Error in destroying the group";
        });

        // Remove the db from the dbs_ list and check if count matches with repl_device
        for (auto it = dbs_.begin(); it != dbs_.end(); ++it) {
            if (*it == db) {
                dbs_.erase(it);
                break;
            }
        }

        if (wait_for_removal) { wait_for_listener_destroy(dbs_.size()); }
    }

    void wait_for_listener_destroy(uint64_t exp_listeners) {
        while (true) {
            auto total_listeners = g_helper->num_listeners();
            if (total_listeners == exp_listeners) { break; }
            std::this_thread::sleep_for(std::chrono::milliseconds(100));
        }
    }

    void restart_replica(uint16_t replica, uint32_t shutdown_delay_sec = 5u) {
        if (g_helper->replica_num() == replica) {
            LOGINFO("Restart homestore: replica_num = {}", replica);
            g_helper->restart(shutdown_delay_sec);
            // g_helper->sync_for_test_start();
        } else {
            LOGINFO("Wait for replica={} to completely go down and removed from alive raft-groups", replica);
            std::this_thread::sleep_for(std::chrono::seconds{5});
        }
    }

    void shutdown_replica(uint16_t replica) {
        if (g_helper->replica_num() == replica) {
            LOGINFO("Shutdown homestore: replica_num = {}", replica);
            g_helper->shutdown();
        } else {
            LOGINFO("Wait for replica={} to completely go down and removed from alive raft-groups", replica);
            std::this_thread::sleep_for(std::chrono::seconds{5});
        }
    }

    void start_replica(uint16_t replica) {
        if (g_helper->replica_num() == replica) {
            LOGINFO("Start homestore: replica_num = {}", replica);
            g_helper->start();
        }
    }

    void create_snapshot() { dbs_[0]->create_snapshot(); }
    void truncate(int num_reserved_entries) { dbs_[0]->truncate(num_reserved_entries); }
    repl_lsn_t get_truncation_upper_limit() { return dbs_[0]->get_truncation_upper_limit(); }

    void replace_member(std::shared_ptr< TestReplicatedDB > db, std::string& task_id, replica_id_t member_out,
                        replica_id_t member_in, uint32_t commit_quorum = 0,
                        ReplServiceError error = ReplServiceError::OK) {
        this->run_on_leader(db, [this, error, db, &task_id, member_out, member_in, commit_quorum]() {
            LOGINFO("Start replace member task_id={}, out={}, in={}", task_id, boost::uuids::to_string(member_out),
                    boost::uuids::to_string(member_in));

            replica_member_info out{member_out, ""};
            replica_member_info in{member_in, ""};
            auto result =
                hs()->repl_service().replace_member(db->repl_dev()->group_id(), task_id, out, in, commit_quorum).get();
            if (error == ReplServiceError::OK) {
                ASSERT_EQ(result.hasError(), false) << "Error in replacing member, err=" << result.error();
            } else {
                ASSERT_EQ(result.hasError(), true);
                ASSERT_EQ(result.error(), error) << "Error in replacing member, err=" << result.error();
            }
        });
    }

    ReplaceMemberStatus check_replace_member_status(std::shared_ptr< TestReplicatedDB > db, std::string& task_id,
                                                    replica_id_t member_out, replica_id_t member_in) {
        LOGINFO("check replace member status, task_id={}, out={} in={}", task_id, boost::uuids::to_string(member_out),
                boost::uuids::to_string(member_in));

        replica_member_info out{member_out, ""};
        replica_member_info in{member_in, ""};
        std::vector< replica_member_info > others;
        for (auto m : g_helper->members_) {
            if (m.first != member_out && m.first != member_in) {
                others.emplace_back(replica_member_info{.id = m.first, .name = ""});
            }
        }
        return hs()->repl_service().get_replace_member_status(db->repl_dev()->group_id(), task_id, out, in, others);
    }

protected:
    std::vector< std::shared_ptr< TestReplicatedDB > > dbs_;
    uint32_t written_entries_{0};

#ifdef _PRERELEASE
    flip::FlipClient m_fc{iomgr_flip::instance()};
#endif
};
