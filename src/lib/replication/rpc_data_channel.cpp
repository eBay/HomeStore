#include "rpc_data_channel_include.h"

#include <sisl/fds/buffer.hpp>
#include <homestore/blk.h>

namespace homestore {

data_rpc_generator::data_rpc_generator(uuid_t group_id, uint32_t replica_id) :
        m_group_id{group_id}, m_replica_id{replica_id} {}

sisl::io_blob_list_t data_rpc_generator::serialize(BlkId const& blkid, sisl::blob const& usr_header,
                                                   sisl::sg_list const& value) {
    auto total_hdr_size =
        sisl::round_up(sizeof(data_channel_rpc_hdr) + sizeof(blk_info_serialized) + usr_header.size, 512);

    uint8_t* bytes = new uint8_t[total_hdr_size];
    uint8_t* cur_ptr = bytes;
    auto* rpc_hdr = new (cur_ptr) data_channel_rpc_hdr();
    rpc_hdr->total_header_size = total_hdr_size;
    rpc_hdr->group_id = m_group_id;
    rpc_hdr->issuer_replica_id = m_replica_id;
    rpc_hdr->num_blocks = 1;
    cur_ptr += sizeof(data_channel_rpc_hdr);

    auto binfo = new (cur_ptr) blk_info_serialized(blkid, usr_header.size);
    cur_ptr += sizeof(blk_info_serialized);
    std::memcpy(cur_ptr, usr_header.bytes, usr_header.size);

    auto io_list = sisl::io_blob::sg_list_to_ioblob_list(value);
    io_list.insert(io_list.begin(), sisl::io_blob(bytes, total_hdr_size, false));
    return io_list;
}

sisl::io_blob_list_t data_rpc_generator::serialize(blkid_list_t const& blkids, sisl::sg_list const& value) {
    auto total_hdr_size =
        sisl::round_up(sizeof(data_channel_rpc_hdr) + (blkids.size * sizeof(blk_info_serialized)), 512);

    uint8_t* bytes = new uint8_t[total_hdr_size];
    uint8_t* cur_ptr = bytes;
    auto* rpc_hdr = new (cur_ptr) data_channel_rpc_hdr();
    rpc_hdr->total_header_size = total_hdr_size;
    rpc_hdr->group_id = m_group_id;
    rpc_hdr->issuer_replica_id = m_replica_id;
    rpc_hdr->num_blocks = blkids.size();
    cur_ptr += sizeof(data_channel_rpc_hdr);

    for (auto const& b : blkids) {
        new (cur_ptr) blk_info_serialized(b, 0);
        cur_ptr += sizeof(blk_info_serialized);
    }

    auto io_list = sisl::io_blob::sg_list_to_ioblob_list(value);
    io_list.insert(io_list.begin(), sisl::io_blob(bytes, total_hdr_size, false));
    return io_list;
}

data_rpc_iterator data_rpc_generator::deserialize(sisl::io_blob const& incoming_buf) {
    auto* rpc_hdr = r_cast< data_channel_rpc_hdr* >(incoming_buf.bytes);
    if (rpc_hdr->major_version != data_channel_rpc_hdr::MAJOR_VERSION) {
        throw std::runtime_error("Incompatible rpc version {} in data channel", rpc_hdr->major_version);
    }

    if (rpc_hdr->group_id != m_group_id) {
        throw std::runtime_error("Reached wrong destination intended group_id={} this_group_id={}", rpc_hdr->group_id,
                                 m_group_id);
    }

    return data_rpc_iterator{incoming_buf};
}

bool data_rpc_iterator::has_more() const { return (next_blk < rpc_hdr->num_blocks); }

std::tuple< RemoteBlkId, sisl::blob, sisl::blob > data_rpc_iterator::next() {
    blk_info_serialized* b = r_cast< blk_info_serialized >(blkid_ptr);
    blkid_ptr += sizeof(blk_info_serialized);

    auto usr_hdr = sisl::blob{.bytes = blkid_ptr, .size = b->user_header_size};
    blkid_ptr += b->user_header_size;
    ++next_blk;

    auto value = sisl::io_blob{value_ptr, b->blkid.get_nblks() * data_service().get_blk_size()};
    value_ptr += value.size;
    return std::tuple(RemoteBlkId{rpc_hdr->issuer_replica_id, b->blkid}, usr_hdr, value);
}

void data_rpc_generator::deserialize(sisl::io_blob const& incoming_buf, remote_blkid_list_t& remote_blkids,
                                     sisl::sg_list& value) {
    auto* rpc_hdr = r_cast< data_channel_rpc_hdr* >(incoming_buf.bytes);
    if (rpc_hdr->major_version != data_channel_rpc_hdr::MAJOR_VERSION) {
        throw std::runtime_error("Incompatible rpc version {} in data channel", rpc_hdr->major_version);
    }

    if (rpc_hdr->group_id != m_group_id) {
        throw std::runtime_error("Reached wrong destination intended group_id={} this_group_id={}", rpc_hdr->group_id,
                                 m_group_id);
    }

    auto cur_ptr = incoming_buf.bytes + sizeof(data_channel_rpc_hdr);
    for (uint32_t i{0}; i < rpc_hdr->num_blocks; ++i) {
        blk_info_serialized* b = r_cast< blk_info_serialized >(cur_ptr);
        remote_blkids.emplace_back(rpc_hdr->issuer_replica_id, rpc_hdr->pba, rpc->pba_area[0].pinfo[i].data_size);
    }
    value.size = incoming_buf.size - data_channel_rpc_hdr::max_hdr_size;
    value.iovs.emplace_back(
        iovec{r_cast< void* >(incoming_buf.bytes + data_channel_rpc_hdr::max_hdr_size), value.size});
}

void data_rpc::deserialize(sisl::io_blob const& incoming_buf, data_channel_rpc_hdr& common_header, pba_list_t& pbas) {
    // assert buf.size >= max header size
    data_rpc* rpc = r_cast< data_rpc* >(incoming_buf.bytes);
    common_header = rpc->common_hdr;
    for (uint16_t i{0}; i < rpc->pba_area[0].n_pbas; ++i) {
        pbas.emplace_back(rpc->pba_area[0].pinfo[i].pba);
    }
}

} // namespace homestore

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif