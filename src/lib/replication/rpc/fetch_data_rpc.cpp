#include "fetch_rpc_data.h"

#include <sisl/fds/buffer.hpp>
#include <homestore/blk.h>

namespace homestore {

void FetchRPC::schedule_fetch_and_write(std::vector< shared< repl_req > > const& reqs) {
    // Prepare the rpc request packet with all repl_reqs details
    io_blob_list_t pkts = fetch_data_request::serialize(this, reqs);
    m_sm->mesg_service().data_service_request(FETCH_DATA, pkts, [this, pkts](sisl::io_blob const& incoming_buf) {
        fetch_data_request::free(this, pkts); // TODO: Make this as generic RAII
        on_fetch_data_response_received(incoming_buf);
    });
}

void FetchRPC::on_fetch_data_request(sisl::io_blob const& incoming_buf, intrusive< sisl::GenericRpcData >& rpc_data) {
    validate_header(incoming_buf);

    auto result = std::make_unique< fetch_data_response::fetch_result >(this);
    auto fetch_it = fetch_data_request::deserialize(incoming_buf.bytes);
    while (fetch_it.has_more()) {
        auto const [usr_hdr, key, lsn, req_blkid] = fetch_it.next();
        if (req_blkid.server_id == m_sm->my_replica_id()) {
            // We are being asked to provide our blkid, hence use direct path to async read the id and return
            BlkId local_blkid = req_blkid->blkid;
            uint64_t size = (local_blkid.get_nblks() * data_service().get_blk_size());

            uint8_t* buf = iomanager.iobuf_alloc(512, size);
            result->add(req_blkid, lsn, buf, size, data_service().async_read(local_blkid, buf, size));
        } else {
            // TODO: Add logic here to read data from lsn and respond with actual data
            // For now returning error
        }
    }

    // set the completion callback
    rpc_data->set_comp_cb(
        [this](boost::intrusive_ptr< sisl::GenericRpcData >& rpc_data) { on_fetch_data_request_completed(rpc_data); });

    if (result->has_result()) {
        // TODO: Change this to folly::Expected instead of bool success/failure
        folly::collectAllUnsafe(result->get_completions())
            .thenValue([rpc_data = std::move(rpc_data), result = std::move(result)](auto&& is_success) {
                auto* raw_result = result.get();
                auto response_blobs = fetch_data_response::serialize(this, FetchRPCStatus::SUCCESS, raw_result);
                rpc_data->set_context(std::move(result));
                raw_result->repl_dev()->send_data_service_response(response_blobs, rpc_data);
            });
    }
}

void FetchRPC::on_fetch_data_request_completed(intrusive< sisl::GenericRpcData >& rpc_data) {
    auto result = dynamic_cast< fetch_data_response::fetch_result* >(rpc_data->get_context());
    assert(result != nullptr);
    for (auto& iov : result->values().iovs) {
        iomanager.iobuf_free(uintptr_cast(iov.iov_base));
        iov.iov_base = nullptr;
        iov.iov_len = 0;
    }

    free_header< fetch_data_response >(result->response_header);
}

void FetchRPC::on_fetch_data_response_received(sisl::io_blob const& incoming_buf) {
    // deserialize incoming buf and get remote blkid list and the data to be written
    validate_header(incoming_buf);

    auto fetch_it = fetch_data_response::deserialize(incoming_buf.bytes);
    while (fetch_it.has_more()) {
        auto const [remote_blkid, lsn, data] = fetch_it.next();

        auto req = m_sm->mapper_find_req(remote_blkid);
        if ((req == nullptr) || req->set_data_writing()) {
            data_service()
                .async_write(data.bytes, data.size, req->local_blkid)
                .thenValue([this, req = std::move(req)](auto&&) {
                    req->set_data_write_completed();
                    m_sm->mapper_remove_req(req->remote_blkid);
                    req->write_comp_promise.setValue();
                });
        } else {
            RD_LOG(DEBUG, "Duplicate fetch of remote_blkid={} data, previous one was processed, ignoring this fetch",
                   remote_blkid);
        }
    }

    msg_service().send_data_service_response({}, rpc_data);
}

void FetchRPC::validate_header(sisl::io_blob const& incoming_buf) {
    data_channel_rpc_hdr* hdr = r_cast< data_channel_rpc_hdr* >(incoming_buf.bytes);
    if (hdr->major_version != data_channel_rpc_hdr::MAJOR_VERSION) {
        throw std::runtime_error("Incompatible rpc version {} in data channel", hdr->major_version);
    }

    if (hdr->group_id != m_group_id) {
        throw std::runtime_error("Reached wrong destination intended group_id={} this_group_id={}", hdr->group_id,
                                 m_group_id);
    }
}
} // namespace homestore