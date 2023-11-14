#pragma once
#include <cstdint>
#include <boost/uuid/uuid.h>

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
};
#pragma pack()

template < typename T >
std::pair< T*, io_blob_list_t > prepare_header(uint32_t group_id, uint32_t replica_id, uint32_t addln_size) {
    auto total_hdr_size = sisl::round_up(sizeof(T) + addln_size, 512);

    uint8_t* hdr = new uint8_t[total_hdr_size];
    auto* rpc = new (hdr) T();
    rpc->total_header_size = total_hdr_size;
    rpc->group_id = group_id;
    rpc->issuer_replica_id = replica_id;

    sisl::io_blob_list_t pkts;
    pkts.push_back(sisl::io_blob{hdr, total_hdr_size, false /* aligned*/});
    return std::pair(rpc, pkts);
}

template < typename T >
void free_header(uint8_t* hdr) {
    T::~T(hdr);
    delete[] hdr;
}
} // namespace homestore