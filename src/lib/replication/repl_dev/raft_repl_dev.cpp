#include <flatbuffers/idl.h>
#include <flatbuffers/minireflect.h>
#include <folly/executors/InlineExecutor.h>
#include <iomgr/iomgr_flip.hpp>
#include <boost/lexical_cast.hpp>

#include <sisl/fds/buffer.hpp>
#include <sisl/grpc/generic_service.hpp>
#include <sisl/grpc/rpc_client.hpp>
#include <homestore/blkdata_service.hpp>
#include <homestore/logstore_service.hpp>
#include <homestore/superblk_handler.hpp>

#include "common/homestore_assert.hpp"
#include "common/homestore_config.hpp"
// #include "common/homestore_flip.hpp"
#include "replication/service/raft_repl_service.h"
#include "replication/repl_dev/raft_repl_dev.h"
#include "push_data_rpc_generated.h"
#include "fetch_data_rpc_generated.h"

namespace homestore {
std::atomic< uint64_t > RaftReplDev::s_next_group_ordinal{1};

RaftReplDev::RaftReplDev(RaftReplService& svc, superblk< raft_repl_dev_superblk >&& rd_sb, bool load_existing) :
        m_repl_svc{svc},
        m_msg_mgr{svc.msg_manager()},
        m_group_id{rd_sb->group_id},
        m_my_repl_id{svc.get_my_repl_uuid()},
        m_raft_server_id{nuraft_mesg::to_server_id(m_my_repl_id)},
        m_rd_sb{std::move(rd_sb)},
        m_metrics{fmt::format("{}_{}", group_id_str(), m_raft_server_id).c_str()} {
    m_state_machine = std::make_shared< RaftStateMachine >(*this);

    if (load_existing) {
        m_data_journal =
            std::make_shared< ReplLogStore >(*this, *m_state_machine, m_rd_sb->logdev_id, m_rd_sb->logstore_id);
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
                .open_log_store(m_rd_sb->logdev_id, m_rd_sb->free_blks_journal_id, false)
                .thenValue([this](auto log_store) {
                    m_free_blks_journal = std::move(log_store);
                    m_rd_sb->free_blks_journal_id = m_free_blks_journal->get_store_id();
                });
        }
    } else {
        m_data_journal = std::make_shared< ReplLogStore >(*this, *m_state_machine);
        m_rd_sb->logdev_id = m_data_journal->logdev_id();
        m_rd_sb->logstore_id = m_data_journal->logstore_id();
        m_rd_sb->last_applied_dsn = 0;
        m_rd_sb->group_ordinal = s_next_group_ordinal.fetch_add(1);
        m_rdev_name = fmt::format("rdev{}", m_rd_sb->group_ordinal);

        if (m_rd_sb->is_timeline_consistent) {
            m_free_blks_journal = logstore_service().create_new_log_store(m_rd_sb->logdev_id, false /* append_mode */);
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
    rreq->rkey = repl_key{.server_id = server_id(), .term = raft_server()->get_term(), .dsn = m_next_dsn.fetch_add(1)};

    // Add the request to the repl_dev_rreq map, it will be accessed throughout the life cycle of this request
    auto const [it, happened] = m_repl_key_req_map.emplace(rreq->rkey, rreq);
    RD_DBG_ASSERT(happened, "Duplicate repl_key={} found in the map", rreq->rkey.to_string());

    // If it is header only entry, directly propose to the raft
    if (rreq->value.size) {
        rreq->value_inlined = false;
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
                auto raft_status = m_state_machine->propose_to_raft(std::move(rreq));
                if (raft_status != ReplServiceError::OK) { handle_error(rreq, raft_status); }
            } else {
                HS_DBG_ASSERT(false, "Error in writing data");
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            }
        });
    } else {
        rreq->value_inlined = true;
        RD_LOG(DEBUG, "Skipping data channel send since value size is 0");
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

    RD_LOG(DEBUG, "Data Channel: Pushing data to all followers: rreq=[{}]", rreq->to_compact_string());

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
            RD_LOG(DEBUG, "Data Channel: Data push completed for rreq=[{}]", rreq->to_compact_string());
            rreq->fb_builder.Release();
            rreq->pkts.clear();
        });
}

void RaftReplDev::on_fetch_data_received(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto const& incoming_buf = rpc_data->request_blob();
    auto fetch_req = GetSizePrefixedFetchData(incoming_buf.cbytes());

    RD_LOG(DEBUG, "Data Channel: FetchData received: fetch_req.size={}", fetch_req->request()->entries()->size());

    std::vector< sisl::sg_list > sgs_vec;

    struct Context {
        std::condition_variable cv;
        std::mutex mtx;
        size_t outstanding_read_cnt;
    };

    auto ctx = std::make_shared< Context >();
    ctx->outstanding_read_cnt = fetch_req->request()->entries()->size();

    for (auto const& req : *(fetch_req->request()->entries())) {
        auto const& lsn = req->lsn();
        auto const& originator = req->blkid_originator();
        auto const& remote_blkid = req->remote_blkid();

        RD_LOG(DEBUG, "Data Channel: FetchData received: lsn={}", lsn);

        // release this assert if in the future we want to fetch from non-originator;
        RD_REL_ASSERT(originator == server_id(),
                      "Not expect to receive fetch data from remote when I am not the originator of this request");

        // fetch data based on the remote_blkid
        if (originator == server_id()) {
            // We are the originator of the blkid, read data locally;
            MultiBlkId local_blkid;

            // convert remote_blkid serialized data to local blkid
            local_blkid.deserialize(sisl::blob{remote_blkid->Data(), remote_blkid->size()}, true /* copy */);

            // prepare the sgs data buffer to read into;
            auto const total_size = local_blkid.blk_count() * get_blk_size();
            sisl::sg_list sgs;
            sgs.size = total_size;
            sgs.iovs.emplace_back(
                iovec{.iov_base = iomanager.iobuf_alloc(get_blk_size(), total_size), .iov_len = total_size});

            // accumulate the sgs for later use (send back to the requester));
            sgs_vec.push_back(sgs);

            async_read(local_blkid, sgs, total_size).thenValue([this, &ctx](auto&& err) {
                if (err) {
                    COUNTER_INCREMENT(m_metrics, read_err_cnt, 1);
                    RD_REL_ASSERT(false, "Error in reading data"); // TODO: Find a way to return error to the Listener
                }

                {
                    std::unique_lock< std::mutex > lk{ctx->mtx};
                    --(ctx->outstanding_read_cnt);
                }
                ctx->cv.notify_one();
            });
        }
    }

    {
        // wait for read to complete;
        std::unique_lock< std::mutex > lk{ctx->mtx};
        ctx->cv.wait(lk, [&ctx] { return (ctx->outstanding_read_cnt == 0); });
    }

    // now prepare the io_blob_list to response back to requester;
    nuraft_mesg::io_blob_list_t pkts = sisl::io_blob_list_t{};
    for (auto const& sgs : sgs_vec) {
        auto const ret = sisl::io_blob::sg_list_to_ioblob_list(sgs);
        pkts.insert(pkts.end(), ret.begin(), ret.end());
    }

    // copy by value to avoid since it is on stack;
    rpc_data->set_comp_cb([sgs_vec](boost::intrusive_ptr< sisl::GenericRpcData >&) {
        for (auto const& sgs : sgs_vec) {
            for (auto const& iov : sgs.iovs) {
                iomanager.iobuf_free(reinterpret_cast< uint8_t* >(iov.iov_base));
            }
        }
    });

    group_msg_service()->send_data_service_response(pkts, rpc_data);
}

void RaftReplDev::handle_error(repl_req_ptr_t const& rreq, ReplServiceError err) {
    if (err == ReplServiceError::OK) { return; }

    auto s = rreq->state.load();
    if ((s & uint32_cast(repl_req_state_t::ERRORED)) ||
        !(rreq->state.compare_exchange_strong(s, s | uint32_cast(repl_req_state_t::ERRORED)))) {
        RD_LOG(ERROR, "Raft Channel: Error in processing rreq=[{}] error={} already errored", rreq->to_compact_string(),
               err);
        return;
    }

    // Free the blks which is allocated already
    RD_LOG(ERROR, "Raft Channel: Error in processing rreq=[{}] error={}", rreq->to_compact_string(), err);
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

    auto rreq = applier_create_req(
        repl_key{.server_id = push_req->issuer_replica_id(), .term = push_req->raft_term(), .dsn = push_req->dsn()},
        header, key, push_req->data_size());
    rreq->rpc_data = rpc_data;
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("simulate_fetch_remote_data")) {
        LOGINFO("Data Channel: Flip is enabled, skip on_push_data_received to simulate fetch remote data, "
                "server_id={}, term={}, dsn={}",
                push_req->issuer_replica_id(), push_req->raft_term(), push_req->dsn());
        return;
    }
#endif
    RD_LOG(DEBUG, "Data Channel: Received data rreq=[{}]", rreq->to_compact_string());

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
                COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
                RD_DBG_ASSERT(false, "Error in writing data");
                handle_error(rreq, ReplServiceError::DRIVE_WRITE_ERROR);
            } else {
                rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
                rreq->data_written_promise.setValue();
                RD_LOG(DEBUG, "Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
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

repl_req_ptr_t RaftReplDev::repl_key_to_req(repl_key const& rkey) const {
    auto const it = m_repl_key_req_map.find(rkey);
    if (it == m_repl_key_req_map.cend()) { return nullptr; }
    return it->second;
}

repl_req_ptr_t RaftReplDev::applier_create_req(repl_key const& rkey, sisl::blob const& user_header,
                                               sisl::blob const& user_key, uint32_t data_size) {
    auto const [it, happened] = m_repl_key_req_map.try_emplace(rkey, repl_req_ptr_t(new repl_req_ctx()));
    RD_DBG_ASSERT((it != m_repl_key_req_map.end()), "Unexpected error in map_repl_key_to_req");
    auto rreq = it->second;

    // There is no data portion, so there is not requied to allocate
    if (data_size == 0) {
        rreq->rkey = rkey;
        rreq->header = user_header;
        rreq->key = user_key;
        rreq->value_inlined = true;
        return rreq;
    }

    if (!happened) {
        // We already have the entry in the map, check if we are already allocated the blk by previous caller, in that
        // case we need to return the req.
        if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) {
            // Do validation if we have the correct mapping
            RD_REL_ASSERT(blob_equals(user_header, rreq->header), "User header mismatch for repl_key={}",
                          rkey.to_string());
            RD_REL_ASSERT(blob_equals(user_key, rreq->key), "User key mismatch for repl_key={}", rkey.to_string());
            RD_LOG(DEBUG, "Repl_key=[{}] already received  ", rkey.to_string());
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
    rreq->value_inlined = false;
    rreq->local_blkid = do_alloc_blk(data_size, m_listener->get_blk_alloc_hints(user_header, data_size));
    rreq->state.fetch_or(uint32_cast(repl_req_state_t::BLK_ALLOCATED));

    RD_LOG(DEBUG, "in applier_create_req: rreq={}", rreq->to_compact_string());

    return rreq;
}

static auto get_max_data_fetch_size() {
#ifdef _PRERELEASE
    if (iomgr_flip::instance()->test_flip("simulate_staging_fetch_data")) {
        LOGINFO("Flip simulate_staging_fetch_data is enabled, return max_data_fetch_size: 16K");
        return 4 * 4096ull;
    }
#endif
    return HS_DYNAMIC_CONFIG(consensus.data_fetch_max_size_mb) * 1024 * 1024ull;
}

void RaftReplDev::check_and_fetch_remote_data(std::vector< repl_req_ptr_t >* rreqs) {
    // Pop any entries that are already completed - from the entries list as well as from map
    rreqs->erase(std::remove_if(rreqs->begin(), rreqs->end(),
                                [this](repl_req_ptr_t const& rreq) {
                                    if (rreq == nullptr) { return true; }

                                    if (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
                                        RD_LOG(DEBUG, "Raft Channel: Data write completed and blkid mapped: rreq=[{}]",
                                               rreq->to_compact_string());
                                        return true; // Remove from the pending list
                                    } else {
                                        return false;
                                    }
                                }),
                 rreqs->end());

    if (rreqs->size()) {
        // Some data not completed yet, let's fetch from remote;
        auto total_size_to_fetch = 0ul;
        std::vector< repl_req_ptr_t > next_batch_rreqs;
        const auto max_batch_size = get_max_data_fetch_size();
        for (auto const& rreq : *rreqs) {
            auto const& size = rreq->remote_blkid.blkid.blk_count() * get_blk_size();
            if ((total_size_to_fetch + size) >= max_batch_size) {
                fetch_data_from_remote(std::move(next_batch_rreqs));
                next_batch_rreqs.clear();
                total_size_to_fetch = 0;
            }

            total_size_to_fetch += size;
            next_batch_rreqs.emplace_back(rreq);
        }

        // check if there is any left over not processed;
        if (next_batch_rreqs.size()) { fetch_data_from_remote(std::move(next_batch_rreqs)); }
    }
}

void RaftReplDev::fetch_data_from_remote(std::vector< repl_req_ptr_t > rreqs) {
    if (rreqs.size() == 0) { return; }

    std::vector<::flatbuffers::Offset< RequestEntry > > entries;
    entries.reserve(rreqs.size());

    shared< flatbuffers::FlatBufferBuilder > builder = std::make_shared< flatbuffers::FlatBufferBuilder >();
    RD_LOG(DEBUG, "Data Channel : FetchData from remote: rreq.size={}, my server_id={}", rreqs.size(), server_id());
    auto const& originator = rreqs.front()->remote_blkid.server_id;

    for (auto const& rreq : rreqs) {
        entries.push_back(CreateRequestEntry(*builder, rreq->get_lsn(), rreq->term(), rreq->dsn(),
                                             builder->CreateVector(rreq->header.cbytes(), rreq->header.size()),
                                             builder->CreateVector(rreq->key.cbytes(), rreq->key.size()),
                                             rreq->remote_blkid.server_id /* blkid_originator */,
                                             builder->CreateVector(rreq->remote_blkid.blkid.serialize().cbytes(),
                                                                   rreq->remote_blkid.blkid.serialized_size())));
        // releax this assert if there is a case in same batch originator can be different (can't think of one now)
        // but if there were to be such case, we need to group rreqs by originator and send them in separate
        // batches;
        RD_DBG_ASSERT(rreq->remote_blkid.server_id == originator, "Unexpected originator for rreq={}",
                      rreq->to_compact_string());

        RD_LOG(TRACE, "Fetching data from originator={}, remote: rreq=[{}], remote_blkid={}, my server_id={}",
               originator, rreq->to_compact_string(), rreq->remote_blkid.blkid.to_string(), server_id());
    }

    builder->FinishSizePrefixed(
        CreateFetchData(*builder, CreateFetchDataRequest(*builder, builder->CreateVector(entries))));

    COUNTER_INCREMENT(m_metrics, fetch_rreq_cnt, 1);
    COUNTER_INCREMENT(m_metrics, fetch_total_entries_cnt, rreqs.size());

    // leader can change, on the receiving side, we need to check if the leader is still the one who originated the
    // blkid;
    group_msg_service()
        ->data_service_request_bidirectional(
            originator, FETCH_DATA,
            sisl::io_blob_list_t{
                sisl::io_blob{builder->GetBufferPointer(), builder->GetSize(), false /* is_aligned */}})
        .via(&folly::InlineExecutor::instance())
        .thenValue([this, builder, rreqs](auto e) {
            if (!e) {
                // if we are here, it means the original who sent the log entries are down.
                // we need to handle error and when the other member becomes leader, it will resend the log entries;
                RD_LOG(ERROR,
                       "Not able to fetching data from originator={}, error={}, probably originator is down. Will "
                       "retry when new leader start appending log entries",
                       rreqs.front()->remote_blkid.server_id, e.error());
                COUNTER_INCREMENT(m_metrics, fetch_err_cnt, 1);
                for (auto const& rreq : rreqs) {
                    handle_error(rreq, RaftReplService::to_repl_error(e.error()));
                }
                return;
            }

            auto raw_data = e.value().response_blob().cbytes();
            auto total_size = e.value().response_blob().size();

            COUNTER_INCREMENT(m_metrics, fetch_total_blk_size, total_size);

            RD_DBG_ASSERT_GT(total_size, 0, "Empty response from remote");
            RD_DBG_ASSERT(raw_data, "Empty response from remote");

            RD_LOG(DEBUG, "Data Channel: FetchData completed for reques.size()={} ", rreqs.size());

            thread_local std::vector< folly::Future< std::error_code > > futs; // static is impplied
            futs.clear();

            for (auto const& rreq : rreqs) {
                auto const data_size = rreq->remote_blkid.blkid.blk_count() * get_blk_size();
                // if data is already received, skip it because someone is already doing the write;
                if (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_RECEIVED)) {
                    // very unlikely to arrive here, but if data got received during we fetch, let the data channel
                    // handle data written;
                    raw_data += data_size;
                    total_size -= data_size;

                    // if blk is already allocated, validate if blk is valid and size matches;
                    RD_DBG_ASSERT(rreq->local_blkid.is_valid(), "Invalid blkid for rreq={}", rreq->to_compact_string());
                    auto const local_size = rreq->local_blkid.blk_count() * get_blk_size();
                    RD_DBG_ASSERT_EQ(data_size, local_size,
                                     "Data size mismatch for rreq={} blkid={}, remote size: {}, local size: {}",
                                     rreq->to_compact_string(), rreq->local_blkid.to_string(), data_size, local_size);

                    RD_LOG(DEBUG, "Data Channel: Data already received for rreq=[{}], skip and move on to next rreq.",
                           rreq->to_compact_string());
                    continue;
                } else {
                    // aquire lock here to avoid two threads are trying to do the same thing;
                    std::unique_lock< std::mutex > lg(rreq->state_mtx);
                    if (rreq->state.load() & uint32_cast(repl_req_state_t::BLK_ALLOCATED)) {
                        // if blk is already allocated, validate if blk is valid and size matches;
                        RD_DBG_ASSERT(rreq->local_blkid.is_valid(), "Invalid blkid for rreq={}",
                                      rreq->to_compact_string());
                        auto const local_size = rreq->local_blkid.blk_count() * get_blk_size();
                        RD_DBG_ASSERT_EQ(data_size, local_size,
                                         "Data size mismatch for rreq={} blkid={}, remote size: {}, local size: {}",
                                         rreq->to_compact_string(), rreq->local_blkid.to_string(), data_size,
                                         local_size);
                    } else {
                        // if blk is not allocated, we need to allocate it;
                        rreq->local_blkid =
                            do_alloc_blk(data_size, m_listener->get_blk_alloc_hints(rreq->header, data_size));

                        // we are about to write the data, so mark both blk allocated and data received;
                        rreq->state.fetch_or(
                            uint32_cast(repl_req_state_t::BLK_ALLOCATED | repl_req_state_t::DATA_RECEIVED));
                    }
                }

                auto data = raw_data;
                if (((uintptr_t)raw_data % data_service().get_align_size()) != 0) {
                    // Unaligned buffer, create a new buffer and copy the entire buf
                    rreq->buf_for_unaligned_data =
                        std::move(sisl::io_blob_safe(data_size, data_service().get_align_size()));
                    std::memcpy(rreq->buf_for_unaligned_data.bytes(), data, data_size);
                    data = rreq->buf_for_unaligned_data.cbytes();
                    RD_DBG_ASSERT(((uintptr_t)data % data_service().get_align_size()) == 0,
                                  "Data is still not aligned after copy");
                }

                // Schedule a write and upon completion, mark the data as written.
                futs.emplace_back(
                    data_service().async_write(r_cast< const char* >(data), data_size, rreq->local_blkid));

                // move the raw_data pointer to next rreq's data;
                raw_data += data_size;
                total_size -= data_size;

                RD_LOG(DEBUG,
                       "Data Channel: Data fetched from remote: rreq=[{}], data_size: {}, total_size: {}, "
                       "local_blkid: {}",
                       rreq->to_compact_string(), data_size, total_size, rreq->local_blkid.to_string());
            }

            folly::collectAllUnsafe(futs).thenValue([this, rreqs, e = std::move(e)](auto&& vf) {
                for (auto const& err_c : vf) {
                    if (sisl_unlikely(err_c.value())) {
                        auto ec = err_c.value();
                        COUNTER_INCREMENT(m_metrics, write_err_cnt, 1);
                        RD_LOG(ERROR, "Error in writing data: {}", ec.value());
                        // TODO: actually will never arrive here as iomgr will assert (should not assert but
                        // to raise alert and leave the raft group);
                    }
                }

                for (auto const& rreq : rreqs) {
                    rreq->state.fetch_or(uint32_cast(repl_req_state_t::DATA_WRITTEN));
                    rreq->data_written_promise.setValue();
                    RD_LOG(TRACE, "Data Channel: Data Write completed rreq=[{}]", rreq->to_compact_string());
                }
            });

            builder->Release();

            RD_DBG_ASSERT_EQ(total_size, 0, "Total size mismatch, some data is not consumed");
        });
}

AsyncNotify RaftReplDev::notify_after_data_written(std::vector< repl_req_ptr_t >* rreqs) {
    std::vector< folly::SemiFuture< folly::Unit > > futs;
    futs.reserve(rreqs->size());

    // Pop any entries that are already completed - from the entries list as well as from map
    rreqs->erase(std::remove_if(rreqs->begin(), rreqs->end(),
                                [this, &futs](repl_req_ptr_t const& rreq) {
                                    if ((rreq == nullptr) || (rreq->value_inlined)) { return true; }

                                    if (rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN)) {
                                        RD_LOG(DEBUG, "Raft Channel: Data write completed and blkid mapped: rreq=[{}]",
                                               rreq->to_compact_string());
                                        return true; // Remove from the pending list
                                    } else {
                                        RD_LOG(TRACE, "Data Channel: Data write pending rreq=[{}]",
                                               rreq->to_compact_string());
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
        m_wait_data_timer_hdl = iomanager.schedule_global_timer( // timer wakes up in current thread;
            HS_DYNAMIC_CONFIG(consensus.wait_data_write_timer_sec) * 1000 * 1000 * 1000, false /* recurring */,
            nullptr /* cookie */, iomgr::reactor_regex::all_worker, [this, rreqs](auto /*cookie*/) {
                RD_LOG(DEBUG, "Data Channel: Wait data write timer fired, checking if data is written");
                check_and_fetch_remote_data(rreqs);
            });
    }

    // block waiting here until all the futs are ready (data channel filled in and promises are made);
    return folly::collectAll(futs).deferValue([this, rreqs](auto&& e) {
        for (auto const& rreq : *rreqs) {
            HS_DBG_ASSERT(rreq->state.load() & uint32_cast(repl_req_state_t::DATA_WRITTEN),
                          "Data written promise raised without updating DATA_WRITTEN state for rkey={}",
                          rreq->rkey.to_string());
            RD_LOG(DEBUG, "Raft Channel: Data write completed and blkid mapped: rreq=[{}]", rreq->to_compact_string());
        }
        RD_LOG(TRACE, "Data Channel: {} pending reqs's data are written", rreqs->size());
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

const replica_id_t RaftReplDev::get_leader_id() const {
    auto leader = m_repl_svc_ctx->raft_leader_id();
    return boost::lexical_cast< replica_id_t >(leader);
}

std::vector< peer_info > RaftReplDev::get_replication_status() const {
    std::vector< peer_info > pi;
    auto rep_status = m_repl_svc_ctx->get_raft_status();
    for (auto const& pinfo : rep_status) {
        pi.emplace_back(peer_info{.id_ = boost::lexical_cast< replica_id_t >(pinfo.id_),
                                  .replication_idx_ = pinfo.last_log_idx_,
                                  .last_succ_resp_us_ = pinfo.last_succ_resp_us_});
    }
    return pi;
}

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

    // Remove the request from repl_key map.
    m_repl_key_req_map.erase(rreq->rkey);

    auto prev_lsn = m_commit_upto_lsn.exchange(rreq->lsn);
    RD_DBG_ASSERT_GT(rreq->lsn, prev_lsn, "Out of order commit of lsns, it is not expected in RaftReplDev");

    RD_LOG(DEBUG, "Raft channel: Commit rreq=[{}]", rreq->to_compact_string());
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
    auto const lsn = m_commit_upto_lsn.load();
    auto const clsn = m_compact_lsn.load();

    if (lsn == m_last_flushed_commit_lsn) {
        // Not dirtied since last flush ignore
        return;
    }
    m_rd_sb->compact_lsn = clsn;
    m_rd_sb->commit_lsn = lsn;
    m_rd_sb->checkpoint_lsn = lsn;
    m_rd_sb->last_applied_dsn = m_next_dsn.load();
    m_rd_sb.write();
    m_last_flushed_commit_lsn = lsn;
}

void RaftReplDev::cp_cleanup(CP*) {}
} // namespace homestore
