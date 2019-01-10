#ifndef _HOMESTORE_HEADER_HPP_
#define _HOMESTORE_HEADER_HPP_

#include <boost/uuid/uuid.hpp>
#include <string>

namespace homeds {
struct blob {
    uint8_t *bytes;
    uint32_t size;
};
}

namespace homestore {

struct dev_info {
    std::string dev_names;
};
}

#endif
