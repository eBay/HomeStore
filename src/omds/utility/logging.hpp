//
// Created by Kadayam, Hari on 15/01/18.
//

#ifndef OMSTORE_LOGGING_HPP
#define OMSTORE_LOGGING_HPP

#include <glog/logging.h>

#define VMODULE_REGISTER_MODULE_SET(setname, module) VLOG_REG_MODULE(setname##module);

#endif //OMSTORE_LOGGING_HPP
