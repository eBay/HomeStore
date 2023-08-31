#pragma once
#include <sisl/utility/enum.hpp>
#include <home_replication/repl_decls.h>

namespace homestore {

#pragma pack(1)
struct data_channel_rpc_hdr {
    static constexpr uint16_t MAJOR_VERSION{0};
    static constexpr uint16_t MINOR_VERSION{1};
    static constexpr uint32_t max_hdr_size{512};

    uint16_t major_version{MAJOR_VERSION};
    uint16_t minor_version{MINOR_VERSION};
    uint32_t total_header_size; // Size of the entire header including
    uuid_t group_id;            // gid of the replica set
    uint32_t issuer_replica_id; // Server ID it is initiated from
    uint32_t num_blocks;        // Number of blocks in this whole request
};
#pragma pack()

#pragma pack(1)
struct blk_info_serialized {
public:
    BlkId blkid;
    uint32_t user_header_size;
    // Followed by user_header

public:
    blk_info_serialized(BlkId const& b, uint32_t s) : blkid{b}, user_header_size{s} {}
};
#pragma pack()

#if 0
#pragma pack(1)
struct data_rpc {
public:
    data_channel_rpc_hdr common_hdr;
    blks_serialized blk_area[0];

public:
    data_rpc() = default;

    static constexpr uint16_t max_blks() {
        return (data_channel_rpc_hdr::max_hdr_size - sizeof(data_rpc) - sizeof(pbas_serialized)) /
            sizeof(pbas_serialized::_pba_info);
    }

    static sisl::io_blob_list_t serialize(const data_channel_rpc_hdr& common_header, const pba_list_t& pbas,
                                          StateMachineStore* store_ptr, const sisl::sg_list& value);

    static void deserialize(sisl::io_blob const& incoming_buf, data_channel_rpc_hdr& common_header,
                            fq_pba_list_t& fq_pbas, sisl::sg_list& value);

    static void deserialize(sisl::io_blob const& incoming_buf, data_channel_rpc_hdr& common_header, pba_list_t& pbas);
};
#pragma pack()
#endif

class data_rpc_generator {
private:
    uuid_t m_group_id;
    uint32_t m_replica_id;

public:
    struct data_rpc_iterator {
        uint32_t next_blk;
        data_channel_rpc_hdr* rpc_hdr;
        uint8_t* blkid_ptr;
        uint8_t* value_ptr;

        data_rpc_iterator(sisl::io_blob const& incoming_buf) :
                next_blk{0},
                rpc_hdr{r_cast< data_channel_rpc_hdr* >(incoming_buf.bytes)},
                blkid_ptr{incoming_buf.bytes + sizeof(data_channel_rpc_hdr)},
                value_ptr{incoming_buf.bytes + rpc_hdr->total_header_size} {}

        bool has_more() const;
        std::tuple< RemoteBlkId, sisl::blob, sisl::blob > data_rpc_generator::next();
    };

public:
    data_rpc_generator(uuid_t group_id, uint32_t replica_id);
    sisl::io_blob_list_t serialize(BlkId const& blkid, sisl::blob const& usr_header, sisl::sg_list const& value);
    sisl::io_blob_list_t serialize(blkid_list_t const& blkids, sisl::sg_list const& value);
    data_rpc_iterator data_rpc_generator::deserialize(sisl::io_blob const& incoming_buf);
}
} // namespace homestore
