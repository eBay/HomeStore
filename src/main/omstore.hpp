//
// Created by Kadayam, Hari on 11/11/17.
//

#ifndef OMSTORE_OMSTORE_HPP
#define OMSTORE_OMSTORE_HPP

namespace omstore {

class OmStore {
public:
    static void init() {
        _instance = new OmStore();
    }

    static OmStore *instance() {
        return _instance;
    }

    OmStore() {
    }

    static OmStore *_instance;
    DeviceManager mgr;
};

//#define DeviceManagerInstance (omstore::OmStore::instance()->mgr)
}
#endif //OMSTORE_OMSTORE_HPP
