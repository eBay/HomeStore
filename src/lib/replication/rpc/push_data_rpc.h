#pragma once
#include <sisl/utility/enum.hpp>
#include <home_replication/repl_decls.h>

#include "replication/rpc/rpc_hdr.h"

namespace homestore {

using repl_req_list_t = std::vector< shared< repl_req > >;

class PushRPC {
public:
    PushRPC(ReplicaStateMachine* sm);

    struct fetch_data_iterator {};

    folly::Future< fetch_data_iterator > fetch(std::vector< std::pair< RemoteBlkId, sisl::blob > >& blkids);
};

#pragma pack(1)
struct push_data_request : public data_channel_rpc_hdr {
    struct req_iterator {
        push_data_request* req_;
        uint32_t next_entry_{0};
        uint8_t* cur_data_ptr_;

        req_iterator(sisl::io_blob const& incoming_buf) :
                req_{r_cast< fetch_data_request* >(incoming_buf.bytes)},
                cur_data_ptr_{incoming_buf.bytes + sizeof(fetch_data_request)} {}

        bool has_more() const { return next_entry_ < req_->num_blocks; }

        std::tuple< sisl::blob, sisl::blob, RemoteBlkId, int64_t > next() {
            auto& e = req_->entries[next_entry_];

            auto usr_hdr = sisl::blob{.bytes = cur_data_ptr_, .size = e.user_header_size};
            cur_data_ptr_ += e.user_header_size;
            auto key = sisl::blob{.bytes = cur_data_ptr_, .size = e.key_size};
            cur_data_ptr_ += e.key_size;

            ++next_entry_;
            return std::tuple(usr_hdr, key, e.remote_blkid, e.lsn);
        }
    };

    repl_key rkey;
    uint32_t user_header_size;
    uint32_t user_key_size;
    uint32_t data_size;

    // Followed by the user_header + user_key + data

    // Followed by the usr_header + key for each entry
    static sisl::io_blob_list_t serialize(PushRPC* p, cshared< repl_req >& req) {
        auto [rpc, pkts] =
            prepare_header< push_data_request >(p->group_id(), p->my_replica_id(), req->header.size + req->key.size);

        rpc->user_header_size = req->header.size;
        rpc->key_size = req->key.size;
        rpc->remote_blkid = RemoteBlkId{p->my_replica_id(), req->blkid};

        auto raw_ptr = r_cast< uint8_t* >(rpc) + sizeof(push_data_request);
        std::memcpy(raw_ptr, req->header.bytes, req->header.size);
        raw_ptr += req->header.size;
        std::memcpy(raw_ptr, req->key.bytes, req->key.size);
        raw_ptr += req->key.size;

        return pkts;
    }

    static req_iterator deserialize(sisl::io_blob const& incoming_buf) { return req_iterator(incoming_buf); }

    static void free(PushRPC* f, sisl::io_blob_list_t const& pkts) {
        f->free_header< fetch_data_request >(pkts[0].bytes);

        for (auto i = 1; i < pkts.size(); ++i) {
            delete io_blob.bytes;
        }
    }
};
#pragma pack()

ENUM(FetchRPCStatus, uint32_t, SUCCESS);

#pragma pack(1)
struct fetch_data_response : public data_channel_rpc_hdr {
    struct resp_entry {
        int64_t lsn;
        RemoteBlkId remote_blkid;
    };

    struct fetch_result {
        std::vector< folly::Future< bool > >* completions;
        sisl::sg_list sgs{.size = 0, .iovs = {}};
        std::vector< std::pair< RemoteBlkId, int64_t > >* req_keys;
        uint8_t* response_header;

        fetch_result() {
            completions = sisl::VectorPool< folly::Future< bool > >::alloc();
            req_keys = sisl::VectorPool< std::pair< RemoteBlkId, int64_t > >::alloc();
        }

        ~fetch_result() {
            sisl::VectorPool< folly::Future< bool > >::free(completions);
            sisl::VectorPool< std::pair< RemoteBlkId, int64_t > >::free(req_keys);
        }

        void add(RemoteBlkId blkid, int64_t lsn, uint8_t* read_buf, uint32_t size, folly::Future< bool >&& comp) {
            req_keys->emplace_back(std::pair(blkid, lsn));
            completions->emplace_back(std::move(comp));
            sgs.size += size;
            sgs.iovs.emplace_back(iovec{.iov_base = buf, .iov_len = size});
        }

        bool has_result() const { return !completions.empty(); }
        uint32_t count() const { return req_keys->size(); }
        const std::vector< folly::Future< bool > >& get_completions() const { return *completions; }

        int64_t nth_lsn(uint32_t n) { return req_keys[n]->second; }
        RemoteBlkId nth_blkid(uint32_t n) { return req_keys[n]->first; }
        const sg_list& values() const { return sgs; }
    };

    FetchRPCStatus status; // Status code for the fetch command
    uint32_t num_blocks;   // Number of blocks in this whole request
    resp_entry entries[0]; // Followed by an array of fetch resp entries

    static sisl::io_blob_list_t serialize(FetchRPC* f, FetchRPCStatus status, fetch_result* result) {
        auto [rpc, bl] = prepare_header< fetch_data_reponse >(f->group_id(), f->my_replica_id(),
                                                              result->count() * sizeof(resp_entry));
        rpc->status = status;
        rpc->num_blocks = result->count();

        for (uint32_t i{0}; i < result->count(); ++i) {
            entries[i]->lsn = result->nth_lsn(i);
            entries[i]->remote_blkid = result->nth_blkid(i);
        }

        result->response_header = uintptr_cast(rpc);
        auto sl = sisl::io_blob::sg_list_to_ioblob_list(result->values());
        bl.insert(bl.end(), sl.begin(), sl.end());
        return bl;
    }

    struct resp_iterator {
        fetch_data_response* resp_;
        uint32_t next_entry_{0};
        uint8_t* data_cur_ptr_;

        req_iterator(sisl::io_blob const& incoming_buf) :
                resp_{r_cast< fetch_data_response* >(incoming_buf.bytes)},
                data_cur_ptr_{incoming_buf.bytes + sizeof(fetch_data_response)} {}

        bool has_more() const { return next_entry_ < resp_->num_blocks; }

        std::tuple< RemoteBlkId, int64_t, sisl::blob > next() {
            auto& e = resp_->entries[next_entry_];

            auto size = e.remote_blkid.blkid.get_nblks() * data_service().get_blk_size();
            auto data = sisl::io_blob{.bytes = cur_data_ptr_, .size = size};
            cur_data_ptr_ += size;

            ++next_entry_;
            return std::tuple(e.remote_blkid, e.lsn, data);
        }
    };
    static resp_iterator deserialize(sisl::io_blob const& incoming_buf) { return resp_iterator(incoming_buf); }
};
#pragma pack()

} // namespace homestore
