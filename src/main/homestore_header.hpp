#ifndef _HOMESTORE_HEADER_HPP_
#define _HOMESTORE_HEADER_HPP_

#include <boost/uuid/uuid.hpp>
#include <string>
namespace homestore {

struct dev_info {
    std::string dev_names;
    boost::uuids::uuid uuid;
};
}

#endif
