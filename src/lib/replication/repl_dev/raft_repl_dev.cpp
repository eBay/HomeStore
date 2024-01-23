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
            logstore_service()
                .open_log_store(LogStoreService::CTRL_LOG_FAMILY_IDX, m_rd_sb->free_blks_journal_id, false)
                .thenValue([this](auto log_store) {
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
    // m_msg_mgr.bind_data_service_request(FETCH_DATA, m_group_id, bind_this(RaftReplDev::on_fetch_data_received, 2));
}

bool RaftReplDev::join_group() {
    auto raft_result =
        m_msg_mgr.join_group(m_group_id, "homestore_replication",
                             std::dynamic_pointer_cast< nuraft_mesg::mesg_state_mgr >(shared_from_this()));
    if (!raft_result) {
        HS_DBG_ASSERT(false, "Unable to join the group_id={} with error={}", boost::uuids::to_string(m_group_id),
                      raft_result.error());
        return false;
    }
    return true;
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
        if (status != BlkAllocStatus::SUCCESS) {
            HS_DBG_ASSERT_EQ(status, BlkAllocStatus::SUCCESS, "Unable to allocate blks");
            handle_error(rreq, ReplServiceError::NO_SPACE_LEFT);
            return;
        }
        rreq->state.fetch_or(uint32_cast(repl_req_state_t::BLK_ALLOCATED));

        // Write the data
        data_service().async_write(rreq->value, rreq->local_blkid).thenValue([this, rreq](auto&& err) {
            if (!err) {
                rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
                auto raft_status = m_state_machine->propose_to_raft(std::move(rreq));
                if (raft_status != ReplServiceError::OK) { handle_error(rreq, raft_status); }
            } else {
                HS_DBG_ASSERT(false, "Error in writing data");
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            }
        });
    } else {
        RD_LOG(INFO, "Skipping data channel send since value size is 0");
        rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
        auto raft_status = m_state_machine->propose_to_raft(std::move(rreq));
        if (raft_status != ReplServiceError::OK) { handle_error(rreq, raft_status); }
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
        .deferValue([this, rreq = std::move(rreq)](auto e) {
            if (e.hasError()) {
                RD_LOG(ERROR, "Data Channel: Error in pushing data to all followers: rreq=[{}] error={}",
                       rreq->to_compact_string(), e.error());
                handle_error(rreq, RaftReplService::to_repl_error(e.error()));
                return;
            }
            // Release the buffer which holds the packets
            RD_LOG(INFO, "Data Channel: Data push completed for rreq=[{}]", rreq->to_compact_string());
            rreq->fb_builder.Release();
            rreq->pkts.clear();
        });
}

void RaftReplDev::handle_error(repl_req_ptr_t const& rreq, ReplServiceError err) {
    if (err == ReplServiceError::OK) { return; }

    auto s = rreq->state.load();
    if ((s & uint32_cast(repl_req_state_t::ERRORED)) ||
        !(rreq->state.compare_exchange_strong(s, s | uint32_cast(repl_req_state_t::ERRORED)))) {
        RD_LOG(INFO, "Raft Channel: Error in processing rreq=[{}] error={} already errored", rreq->to_compact_string(),
               err);
        return;
    }

    // Free the blks which is allocated already
    RD_LOG(INFO, "Raft Channel: Error in processing rreq=[{}] error={}", rreq->to_compact_string(), err);
    if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) {
        auto blkid = rreq->local_blkid;
        data_service().async_free_blk(blkid).thenValue([blkid](auto&& err) {
            HS_LOG_ASSERT(!err, "freeing blkid={} upon error failed, potential to cause blk leak", blkid.to_string());
        });
    }

    HS_DBG_ASSERT(!(rreq->state.load() & uint32_cast(repl_req_state_t::LOG_FLUSHED)),
                  "Unexpected state, received error after log is flushed for rreq=[{}]", rreq->to_compact_string());

    if (rreq->is_proposer) {
        // Notify the proposer about the error
        m_listener->on_error(err, rreq->header, rreq->key, rreq);
        rreq->fb_builder.Release();
        rreq->pkts.clear();
    } else {
        // Complete the response hence proposer can free up its resources
        rreq->header = sisl::blob{};
        rreq->key = sisl::blob{};
        rreq->pkts = sisl::io_blob_list_t{};
        if (rreq->rpc_data) {
            rreq->rpc_data->send_response();
            rreq->rpc_data = nullptr;
        }
    }
}

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
            if (err) {
                RD_DBG_ASSERT(false, "Error in writing data");
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            } else {
                rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
                rreq->data_written_promise.setValue();
                RD_LOG(INFO, "Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
            }
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

#if 0
    // We are yet to support reactive fetch from remote.
    if (m_resync_mode) {
        // if in resync mode, fetch data from remote immediately;
        check_and_fetch_remote_data(std::move(rreqs));
    } else {
        // some blkids are not in completed state, let's schedule a timer to check it again;
        // we wait for data channel to fill in the data. Still if its not done we trigger a fetch from remote;
        m_wait_blkid_write_timer_hdl = iomanager.schedule_thread_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(repl->wait_blkid_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, [this, std::move(rreqs)](auto) {
                check_and_fetch_remote_data(std::move(rreqs));
            });
    }
    return ret;
#endif

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

AsyncReplResult<> RaftReplDev::become_leader() {
    return m_msg_mgr.become_leader(m_group_id).deferValue([this](auto&& e) {
        if (e.hasError()) {
            RD_LOG(ERROR, "Error in becoming leader: {}", e.error());
            return make_async_error<>(RaftReplService::to_repl_error(e.error()));
        }
        return make_async_success<>();
    });
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
    if (rreq->local_blkid.is_valid()) { data_service().commit_blk(rreq->local_blkid); }

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
