#include <flatbuffers/idl.h>
#include <flatbuffers/minireflect.h>
#include <folly/executors/InlineExecutor.h>

#include <sisl/fds/buffer.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/superblk_handler.hpp>

#include "common/homestore_assert.hpp"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/raft_repl_dev.h"
#include "push_data_rpc_generated.h"

namespace homestore {
std::atomic< uint64_t > RaftReplDev::s_next_group_ordinal{1};

RaftReplDev::RaftReplDev(RaftReplService& svc, superblk< raft_repl_dev_superblk >&& rd_sb, bool load_existing) :
        m_repl_svc{svc},
        m_msg_mgr{svc.msg_manager()},
        m_group_id{rd_sb->group_id},
        m_my_repl_id{svc.get_my_repl_uuid()},
        m_raft_server_id{nuraft_mesg::to_server_id(m_my_repl_id)},
        m_rd_sb{std::move(rd_sb)} {
    m_state_machine = std::make_shared< RaftStateMachine >(*this);

    if (load_existing) {
        m_data_journal = std::make_shared< ReplLogStore >(*this, *m_state_machine, m_rd_sb->data_journal_id);
        m_next_dsn = m_rd_sb->last_applied_dsn + 1;
        m_commit_upto_lsn = m_rd_sb->commit_lsn;
        m_last_flushed_commit_lsn = m_commit_upto_lsn;
        m_rdev_name = fmt::format("rdev{}", m_rd_sb->group_ordinal);

        // Its ok not to do compare exchange, because loading is always single threaded as of now
        if (m_rd_sb->group_ordinal >= s_next_group_ordinal.load()) {
            s_next_group_ordinal.store(m_rd_sb->group_ordinal + 1);
        }

        if (m_rd_sb->is_timeline_consistent) {
            logstore_service().open_log_store(LogStoreService::CTRL_LOG_FAMILY_IDX, m_rd_sb->free_blks_journal_id,
                                              false, [this](shared< HomeLogStore > log_store) {
                                                  m_free_blks_journal = std::move(log_store);
                                                  m_rd_sb->free_blks_journal_id = m_free_blks_journal->get_store_id();
                                              });
        }
    } else {
        m_data_journal = std::make_shared< ReplLogStore >(*this, *m_state_machine);
        m_rd_sb->data_journal_id = m_data_journal->logstore_id();
        m_rd_sb->last_applied_dsn = 0;
        m_rd_sb->group_ordinal = s_next_group_ordinal.fetch_add(1);
        m_rdev_name = fmt::format("rdev{}", m_rd_sb->group_ordinal);

        if (m_rd_sb->is_timeline_consistent) {
            m_free_blks_journal =
                logstore_service().create_new_log_store(LogStoreService::CTRL_LOG_FAMILY_IDX, false /* append_mode */);
            m_rd_sb->free_blks_journal_id = m_free_blks_journal->get_store_id();
        }
        m_rd_sb.write();
    }

    RD_LOG(INFO, "Started {} RaftReplDev group_id={}, replica_id={}, raft_server_id={} commited_lsn={} next_dsn={}",
           (load_existing ? "Existing" : "New"), group_id_str(), my_replica_id_str(), m_raft_server_id,
           m_commit_upto_lsn.load(), m_next_dsn.load());

    m_msg_mgr.bind_data_service_request(PUSH_DATA, m_group_id, bind_this(RaftReplDev::on_push_data_received, 1));
    m_msg_mgr.bind_data_service_request(FETCH_DATA, m_group_id, bind_this(RaftReplDev::on_fetch_data_received, 1));
}

void RaftReplDev::use_config(json_superblk raft_config_sb) { m_raft_config_sb = std::move(raft_config_sb); }

void RaftReplDev::async_alloc_write(sisl::blob const& header, sisl::blob const& key, sisl::sg_list const& value,
                                    repl_req_ptr_t rreq) {
    if (!rreq) { auto rreq = repl_req_ptr_t(new repl_req_ctx{}); }
    rreq->header = header;
    rreq->key = key;
    rreq->value = value;

    // If it is header only entry, directly propose to the raft
    if (rreq->value.size) {
        rreq->rkey =
            repl_key{.server_id = server_id(), .term = raft_server()->get_term(), .dsn = m_next_dsn.fetch_add(1)};
        push_data_to_all_followers(rreq);

        // Step 1: Alloc Blkid
        auto status = data_service().alloc_blks(uint32_cast(rreq->value.size),
                                                m_listener->get_blk_alloc_hints(rreq->header, rreq->value.size),
                                                rreq->local_blkid);
        HS_REL_ASSERT_EQ(status, BlkAllocStatus::SUCCESS);

        // Write the data
        data_service().async_write(rreq->value, rreq->local_blkid).thenValue([this, rreq](auto&& err) {
            HS_REL_ASSERT(!err, "Error in writing data"); // TODO: Find a way to return error to the Listener
            rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
            m_state_machine->propose_to_raft(std::move(rreq));
        });
    } else {
        RD_LOG(INFO, "Skipping data channel send since value size is 0");
        rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
        m_state_machine->propose_to_raft(std::move(rreq));
    }
}

void RaftReplDev::push_data_to_all_followers(repl_req_ptr_t rreq) {
    auto& builder = rreq->fb_builder;

    // Prepare the rpc request packet with all repl_reqs details
    builder.FinishSizePrefixed(CreatePushDataRequest(builder, server_id(), rreq->rkey.term, rreq->rkey.dsn,
                                                     builder.CreateVector(rreq->header.cbytes(), rreq->header.size()),
                                                     builder.CreateVector(rreq->key.cbytes(), rreq->key.size()),
                                                     rreq->value.size));

    rreq->pkts = sisl::io_blob::sg_list_to_ioblob_list(rreq->value);
    rreq->pkts.insert(rreq->pkts.begin(), sisl::io_blob{builder.GetBufferPointer(), builder.GetSize(), false});

    /*RD_LOG(INFO, "Data Channel: Pushing data to all followers: rreq=[{}] data=[{}]", rreq->to_string(),
           flatbuffers::FlatBufferToString(builder.GetBufferPointer() + sizeof(flatbuffers::uoffset_t),
                                           PushDataRequestTypeTable()));*/

    RD_LOG(INFO, "Data Channel: Pushing data to all followers: rreq=[{}]", rreq->to_compact_string());

    group_msg_service()
        ->data_service_request_unidirectional(nuraft_mesg::role_regex::ALL, PUSH_DATA, rreq->pkts)
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, rreq = std::move(rreq)](auto e) {
            // Release the buffer which holds the packets
            RD_LOG(INFO, "Data Channel: Data push completed for rreq=[{}]", rreq->to_compact_string());
            rreq->fb_builder.Release();
            rreq->pkts.clear();
        });
}

void RaftReplDev::on_fetch_data_received(intrusive< sisl::GenericRpcData >& rpc_data) {}

void RaftReplDev::on_push_data_received(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto const& incoming_buf = rpc_data->request_blob();
    auto const fb_size =
        flatbuffers::ReadScalar< flatbuffers::uoffset_t >(incoming_buf.cbytes()) + sizeof(flatbuffers::uoffset_t);
    auto push_req = GetSizePrefixedPushDataRequest(incoming_buf.cbytes());
    sisl::blob header = sisl::blob{push_req->user_header()->Data(), push_req->user_header()->size()};
    sisl::blob key = sisl::blob{push_req->user_key()->Data(), push_req->user_key()->size()};

    RD_LOG(TRACE, "PushData received on data channel: {}",
           flatbuffers::FlatBufferToString(incoming_buf.cbytes() + sizeof(flatbuffers::uoffset_t),
                                           PushDataRequestTypeTable()));

    auto rreq = follower_create_req(
        repl_key{.server_id = push_req->issuer_replica_id(), .term = push_req->raft_term(), .dsn = push_req->dsn()},
        header, key, push_req->data_size());
    rreq->rpc_data = rpc_data;

    RD_LOG(INFO, "Data Channel: Received data rreq=[{}]", rreq->to_compact_string());

    if (rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_RECEIVED)) &
        uint32_cast(repl_req_state_t::DATA_RECEIVED)) {
        // We already received the data before, just ignore this data
        // TODO: Should we forcibly overwrite the data with new data?
        return;
    }

    // Get the data portion from the buffer
    HS_DBG_ASSERT_EQ(fb_size + push_req->data_size(), incoming_buf.size(), "Size mismatch of data size vs buffer size");
    uint8_t const* data = incoming_buf.cbytes() + fb_size;

    if (((uintptr_t)data % data_service().get_align_size()) != 0) {
        // Unaligned buffer, create a new buffer and copy the entire buf
        rreq->buf_for_unaligned_data =
            std::move(sisl::io_blob_safe(push_req->data_size(), data_service().get_align_size()));
        std::memcpy(rreq->buf_for_unaligned_data.bytes(), data, push_req->data_size());
        data = rreq->buf_for_unaligned_data.cbytes();
    }

    // Schedule a write and upon completion, mark the data as written.
    data_service()
        .async_write(r_cast< const char* >(data), push_req->data_size(), rreq->local_blkid)
        .thenValue([this, rreq](auto&& err) {
            RD_REL_ASSERT(!err, "Error in writing data"); // TODO: Find a way to return error to the Listener
            rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
            rreq->data_written_promise.setValue();
            RD_LOG(INFO, "Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
        });
}

static bool blob_equals(sisl::blob const& a, sisl::blob const& b) {
    if (a.size() != b.size()) { return false; }
    return (std::memcmp(a.cbytes(), b.cbytes(), a.size()) == 0);
}

static MultiBlkId do_alloc_blk(uint32_t size, blk_alloc_hints const& hints) {
    MultiBlkId blkid;
    auto const status = data_service().alloc_blks(sisl::round_up(size, data_service().get_blk_size()), hints, blkid);
    RELEASE_ASSERT_EQ(status, BlkAllocStatus::SUCCESS, "alloc_blks returned null, no space left!");
    return blkid;
}

repl_req_ptr_t RaftReplDev::follower_create_req(repl_key const& rkey, sisl::blob const& user_header,
                                                sisl::blob const& user_key, uint32_t data_size) {
    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT((it != m_repl_key_req_map.end()), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;

    if (!happened) {
        // We already have the entry in the map, check if we are already allocated the blk by previous caller, in that
        // case we need to return the req.
        if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) {
            // Do validation if we have the correct mapping
            RD_REL_ASSERT(blob_equals(user_header, rreq->header), "User header mismatch for repl_key={}",
                          rkey.to_string());
            RD_REL_ASSERT(blob_equals(user_key, rreq->key), "User key mismatch for repl_key={}", rkey.to_string());
            RD_LOG(INFO, "Repl_key=[{}] already received  ", rkey.to_string());
            return rreq;
        }
    }

    // We need to allocate the block, since entry doesn't exist or if it exist, two threads are trying to do the same
    // thing. So take state mutex and allocate the blk
    std::unique_lock< std::mutex > lg(rreq->state_mtx);
    if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) { return rreq; }
    rreq->rkey = rkey;
    rreq->header = user_header;
    rreq->key = user_key;
    rreq->local_blkid = do_alloc_blk(data_size, m_listener->get_blk_alloc_hints(user_header, data_size));
    rreq->state.fetch_or(uint32_cast(repl_req_state_t::BLK_ALLOCATED));

    return rreq;
}

void RaftReplDev::check_and_fetch_remote_data_if_needed(std::vector< repl_req_ptr_t >* rreqs) {
    // Pop any entries that are already completed - from the entries list as well as from map
    rreqs->erase(std::remove_if(
                     rreqs->begin(), rreqs->end(),
                     [this](repl_req_ptr_t const& rreq) {
                         if (rreq == nullptr) { return true; }

                         if (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
                             m_repl_key_req_map.erase(rreq->rkey); // Remove=Pop from map as well, since it is completed
                             RD_LOG(INFO,
                                    "Raft Channel: Data write completed and blkid mapped, removing from map: rreq=[{}]",
                                    rreq->to_compact_string());
                             return true; // Remove from the pending list
                         } else {
                             return false;
                         }
                     }),
                 rreqs->end());

    if (rreqs->size()) {
        // Some data not completed yet, let's fetch from remote;
        fetch_data_from_leader(rreqs);
    }
}

void RaftReplDev::fetch_data_from_remote(std::vector< repl_req_ptr_t >* rreqs) {
    group_msg_service()->data_service_request_unidirectional(nuraft_mesg::role_regex::ALL, FETCH_DATA, );

#if 0
    m_repl_svc_ctx->data_service_request(
                FETCH_DATA,
                        data_rpc::serialize(data_channel_rpc_hdr{m_group_id, 0 /*replace with replica id*/}, remote_pbas,
                                                        m_state_store.get(), {}),
                                [this](sisl::io_blob const& incoming_buf) {
                                            auto null_rpc_data = boost::intrusive_ptr< sisl::GenericRpcData >(nullptr);
                                                        m_state_machine->on_data_received(incoming_buf, null_rpc_data);
                                                                });
#endif
}

AsyncNotify RaftReplDev::notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs) {
    std::vector< folly::SemiFuture< folly::Unit > > futs;
    futs.reserve(rreqs->size());

    // Pop any entries that are already completed - from the entries list as well as from map
    rreqs->erase(std::remove_if(
                     rreqs->begin(), rreqs->end(),
                     [this, &futs](repl_req_ptr_t const& rreq) {
                         if (rreq == nullptr) { return true; }

                         if (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
                             m_repl_key_req_map.erase(rreq->rkey); // Remove=Pop from map as well, since it is completed
                             RD_LOG(INFO,
                                    "Raft Channel: Data write completed and blkid mapped, removing from map: rreq=[{}]",
                                    rreq->to_compact_string());
                             return true; // Remove from the pending list
                         } else {
                             futs.emplace_back(rreq->data_written_promise.getSemiFuture());
                             return false;
                         }
                     }),
                 rreqs->end());

    // All the entries are done already, no need to wait
    if (rreqs->size() == 0) { return folly::makeFuture< folly::Unit >(folly::Unit{}); }

    // We are yet to support reactive fetch from remote.
    if (is_resync_mode()) {
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_data(rreqs);
    } else {
        // some data are not in completed state, let's schedule a timer to check it again;
        // we wait for data channel to fill in the data. Still if its not done we trigger a fetch from remote;
        m_wait_data_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(consensus.wait_data_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, rreqs](auto) { check_and_fetch_remote_data(rreqs); });
    }

    // block waiting here until all the futs are ready (data channel filled in and promises are made);
    return folly::collectAll(futs).deferValue([this, rreqs](auto&& e) {
        for (auto const& rreq : *rreqs) {
            HS_DBG_ASSERT(rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN),
                          "Data written promise raised without updating DATA_WRITTEN state for rkey={}",
                          rreq->rkey.to_string());
            RD_LOG(INFO, "Raft Channel: Data write completed and blkid mapped, removing from map: rreq=[{}]",
                   rreq->to_compact_string());
            m_repl_key_req_map.erase(rreq->rkey); // Remove from map as well, since it is completed
        }
        return folly::makeSemiFuture< folly::Unit >(folly::Unit{});
    });
}

folly::Future< std::error_code > RaftReplDev::async_read(MultiBlkId const& bid, sisl::sg_list& sgs, uint32_t size,
                                                         bool part_of_batch) {
    return data_service().async_read(bid, sgs, size, part_of_batch);
}

void RaftReplDev::async_free_blks(int64_t, MultiBlkId const& bid) {
    // TODO: For timeline consistency required, we should retain the blkid that is changed and write that to another
    // journal.
    data_service().async_free_blk(bid);
}

bool RaftReplDev::is_leader() const { return m_repl_svc_ctx->is_raft_leader(); }

uint32_t RaftReplDev::get_blk_size() const { return data_service().get_blk_size(); }

nuraft_mesg::repl_service_ctx* RaftReplDev::group_msg_service() { return m_repl_svc_ctx.get(); }
nuraft::raft_server* RaftReplDev::raft_server() { return m_repl_svc_ctx->_server; }

///////////////////////////////////  Config Serialize/Deserialize Section ////////////////////////////////////
static nlohmann::json serialize_server_config(std::list< nuraft::ptr< nuraft::srv_config > > const& server_list) {
    auto servers = nlohmann::json::array();
    for (auto const& server_conf : server_list) {
        if (!server_conf) { continue; }
        servers.push_back(nlohmann::json{{"id", server_conf->get_id()},
                                         {"dc_id", server_conf->get_dc_id()},
                                         {"endpoint", server_conf->get_endpoint()},
                                         {"aux", server_conf->get_aux()},
                                         {"learner", server_conf->is_learner()},
                                         {"priority", server_conf->get_priority()}});
    }
    return servers;
}

static nlohmann::json serialize_cluster_config(const nuraft::cluster_config& config) {
    return nlohmann::json{{"log_idx", config.get_log_idx()},
                          {"prev_log_idx", config.get_prev_log_idx()},
                          {"eventual_consistency", config.is_async_replication()},
                          {"user_ctx", config.get_user_ctx()},
                          {"servers", serialize_server_config(config.get_servers())}};
}

static nuraft::ptr< nuraft::srv_config > deserialize_server_config(nlohmann::json const& server) {
    DEBUG_ASSERT(server.contains("id"), "Missing field")
    auto const id = static_cast< int32_t >(server["id"]);
    DEBUG_ASSERT(server.contains("dc_id"), "Missing field")
    auto const dc_id = static_cast< int32_t >(server["dc_id"]);
    DEBUG_ASSERT(server.contains("endpoint"), "Missing field")
    auto const endpoint = server["endpoint"];
    DEBUG_ASSERT(server.contains("aux"), "Missing field")
    auto const aux = server["aux"];
    DEBUG_ASSERT(server.contains("learner"), "Missing field")
    auto const learner = server["learner"];
    DEBUG_ASSERT(server.contains("priority"), "Missing field")
    auto const prior = static_cast< int32_t >(server["priority"]);
    return nuraft::cs_new< nuraft::srv_config >(id, dc_id, endpoint, aux, learner, prior);
}

static void deserialize_server_list(nlohmann::json const& servers,
                                    std::list< nuraft::ptr< nuraft::srv_config > >& server_list) {
    for (auto const& server_conf : servers) {
        server_list.push_back(deserialize_server_config(server_conf));
    }
}

nuraft::ptr< nuraft::cluster_config > deserialize_cluster_config(nlohmann::json const& cluster_config) {
    DEBUG_ASSERT(cluster_config.contains("log_idx"), "Missing field")
    auto const& log_idx = cluster_config["log_idx"];
    DEBUG_ASSERT(cluster_config.contains("prev_log_idx"), "Missing field")
    auto const& prev_log_idx = cluster_config["prev_log_idx"];
    DEBUG_ASSERT(cluster_config.contains("eventual_consistency"), "Missing field")
    auto const& eventual = cluster_config["eventual_consistency"];

    auto raft_config = nuraft::cs_new< nuraft::cluster_config >(log_idx, prev_log_idx, eventual);
    DEBUG_ASSERT(cluster_config.contains("user_ctx"), "Missing field")
    raft_config->set_user_ctx(cluster_config["user_ctx"]);
    DEBUG_ASSERT(cluster_config.contains("servers"), "Missing field")
    deserialize_server_list(cluster_config["servers"], raft_config->get_servers());
    return raft_config;
}

nuraft::ptr< nuraft::cluster_config > RaftReplDev::load_config() {
    std::unique_lock lg{m_config_mtx};
    auto& js = *m_raft_config_sb;

    if (!js.contains("config")) {
        auto cluster_conf = nuraft::cs_new< nuraft::cluster_config >();
        cluster_conf->get_servers().push_back(
            nuraft::cs_new< nuraft::srv_config >(m_raft_server_id, my_replica_id_str()));
        js["config"] = serialize_cluster_config(*cluster_conf);
    }
    return deserialize_cluster_config(js["config"]);
}

void RaftReplDev::save_config(const nuraft::cluster_config& config) {
    std::unique_lock lg{m_config_mtx};
    (*m_raft_config_sb)["config"] = serialize_cluster_config(config);
    m_raft_config_sb.write();
}

void RaftReplDev::save_state(const nuraft::srv_state& state) {
    std::unique_lock lg{m_config_mtx};
    (*m_raft_config_sb)["state"] = nlohmann::json{{"term", state.get_term()}, {"voted_for", state.get_voted_for()}};
    m_raft_config_sb.write();
}

nuraft::ptr< nuraft::srv_state > RaftReplDev::read_state() {
    std::unique_lock lg{m_config_mtx};
    auto& js = *m_raft_config_sb;
    auto state = nuraft::cs_new< nuraft::srv_state >();
    if (js["state"].empty()) {
        js["state"] = nlohmann::json{{"term", state->get_term()}, {"voted_for", state->get_voted_for()}};
    } else {
        try {
            state->set_term(uint64_cast(js["state"]["term"]));
            state->set_voted_for(static_cast< int >(js["state"]["voted_for"]));
        } catch (std::out_of_range const&) {
            LOGWARN("State data was not in the expected format [group_id={}]!", m_group_id)
        }
    }
    return state;
}

nuraft::ptr< nuraft::log_store > RaftReplDev::load_log_store() { return m_data_journal; }

int32_t RaftReplDev::server_id() { return m_raft_server_id; }

///////////////////////////////////  nuraft_mesg::mesg_state_mgr overrides ////////////////////////////////////
uint32_t RaftReplDev::get_logstore_id() const { return m_data_journal->logstore_id(); }

std::shared_ptr< nuraft::state_machine > RaftReplDev::get_state_machine() { return m_state_machine; }

void RaftReplDev::permanent_destroy() {
    // TODO: Implement this
}
void RaftReplDev::leave() {
    // TODO: Implement this
}

///////////////////////////////////  Private metohds ////////////////////////////////////
void RaftReplDev::report_committed(repl_req_ptr_t rreq) {
    auto prev_lsn = m_commit_upto_lsn.exchange(rreq->lsn);
    RD_DBG_ASSERT_GT(rreq->lsn, prev_lsn, "Out of order commit of lsns, it is not expected in RaftReplDev");

    RD_LOG(INFO, "Raft channel: Commit rreq=[{}]", rreq->to_compact_string());
    m_listener->on_commit(rreq->lsn, rreq->header, rreq->key, rreq->local_blkid, rreq);

    if (!rreq->is_proposer) {
        rreq->header = sisl::blob{};
        rreq->key = sisl::blob{};
        rreq->pkts = sisl::io_blob_list_t{};
        if (rreq->rpc_data) {
            rreq->rpc_data->send_response();
            rreq->rpc_data = nullptr;
        }
    }
}

void RaftReplDev::cp_flush(CP*) {
    auto lsn = m_commit_upto_lsn.load();
    if (lsn == m_last_flushed_commit_lsn) {
        // Not dirtied since last flush ignore
        return;
    }

    m_rd_sb->commit_lsn = lsn;
    m_rd_sb->checkpoint_lsn = lsn;
    m_rd_sb.write();
    m_last_flushed_commit_lsn = lsn;
}

void RaftReplDev::cp_cleanup(CP*) {}
} // namespace homestore
