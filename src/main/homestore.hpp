//
// Created by Kadayam, Hari on 11/11/17.
//

#ifndef OMSTORE_OMSTORE_HPP
#define OMSTORE_OMSTORE_HPP

namespace homestore {

class HomeStore {
public:
    static void init() {
        _instance = new HomeStore();
    }

    static HomeStore *instance() {
        return _instance;
    }

    HomeStore() {
    }

    static HomeStore *_instance;
    DeviceManager mgr;
};

//#define DeviceManagerInstance (homestore::OmStore::instance()->mgr)
}
#endif //OMSTORE_OMSTORE_HPP
