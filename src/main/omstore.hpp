//
// Created by Kadayam, Hari on 11/11/17.
//

#ifndef OMSTORE_OMSTORE_HPP
#define OMSTORE_OMSTORE_HPP

#include "blkdev/blkdev.h"

namespace omstore {

class OmStore {
public:
    static void init() {
        _instance = new OmStore();
    }

    static Omstore *instance() {
        return _instance;
    }

    OmStore() {
    }

    static OmStore *_instance;
    BlkDevManager mgr;
};

OmStore::_instance = nullptr;

#define BlkDevManagerInstance (OmStore::instance()->mgr)

}
#endif //OMSTORE_OMSTORE_HPP
