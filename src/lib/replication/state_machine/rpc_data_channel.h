#pragma once
#include <sisl/utility/enum.hpp>
#include <home_replication/repl_decls.h>

namespace home_replication {

VENUM(data_rpc_name_t, uint16_t, SEND_PBAS = 0, FETCH_PBAS = 1)

#pragma pack(1)
struct data_channel_rpc_hdr {
    static constexpr uint16_t MAJOR_VERSION{0};
    static constexpr uint16_t MINOR_VERSION{1};
    static constexpr uint32_t max_hdr_size{512};

    uint16_t major_version{MAJOR_VERSION};
    uint16_t minor_version{MINOR_VERSION};
    uint32_t total_size{0};     // Total size of RPC including this rpc header
    uuid_t group_id;            // UUID of the replica set
    uint32_t issuer_replica_id; // Server ID it is initiated from
    data_rpc_name_t rpc;        // Name of the RPC
};
#pragma pack()

#pragma pack(1)
struct pbas_serialized {
public:
    struct _pba_info {
        pba_t pba;
        uint32_t data_size;
    };

    uint16_t n_pbas;
    _pba_info pinfo[0];

public:
    static pbas_serialized* serialize(const pba_list_t& pbas, uint8_t* raw_ptr) {
        pbas_serialized* pthis = new (raw_ptr) pbas_serialized();
        pthis->n_pbas = pbas.size();
        for (uint16_t i{0}; i < pthis->n_pbas; ++i) {
            pthis->pinfo[i].pba = pbas[i];
        }
        return pthis;
    }
};
#pragma pack()

#pragma pack(1)
struct send_pbas_rpc {
public:
    data_channel_rpc_hdr common_hdr;
    pbas_serialized pba_area[0];

public:
    send_pbas_rpc() : common_hdr.rpc{data_rpc_name_t::SEND_PBAS} {}

    sisl::blob to_blob() { return sisl::blob{uintptr_cast(this), data_channel_rpc_hdr::max_hdr_size}; }

    static constexpr uint16_t max_pbas() {
        return (data_channel_rpc_hdr::max_hdr_size - sizeof(send_pbas_rpc)) / sizeof(pbas_serialized);
    }

    static send_pbas_rpc* create(const pba_list_t& pbas) {
        if (pbas.size() > max_pbas()) {
            LOGERROR("Exceeds max number of pbas that can be sent in this rpc");
            return nullptr;
        }

        auto* bytes = new uint8_t[data_channel_rpc_hdr::max_hdr_size];
        send_pbas_rpc* rpc = new (bytes) send_pbas_rpc();
        pbas_serialized::serialize(pbas, r_cast< uint8_t* >(pba_area));

        return rpc;
    }
}
#pragma pack()

} // namespace home_replication