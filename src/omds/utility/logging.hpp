//
// Created by Kadayam, Hari on 15/01/18.
//

#ifndef OMSTORE_LOGGING_HPP
#define OMSTORE_LOGGING_HPP

#include <glog/logging.h>
#include <boost/preprocessor.hpp>

#define REG_VMOD(d1, d2, m)           VLOG_REG_MODULE(m);
#define REGISTER_VMODULES(...)        BOOST_PP_SEQ_FOR_EACH(REG_VMOD, , BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define INIT_VMOD(d1, d2, m)          VLOG_DECL_MODULE(m);
#define INIT_VMODULES(...)            BOOST_PP_SEQ_FOR_EACH(INIT_VMOD, ,BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define START_VMOD(d1, d2, m)        \
        if (google::GetVLOGLevel(BOOST_PP_STRINGIZE(m)) == -1) { \
            google::SetVLOGLevel(BOOST_PP_STRINGIZE(m), getenv("GLOG_v") ? atoi(getenv("GLOG_v")) : 0); \
            if (getenv("GLOG_v")) { \
                std::cout << "Loglevel of " << BOOST_PP_STRINGIZE(m) << " set to " << atoi(getenv("GLOG_v")) << "\n"; \
            } else { \
                std::cout << "Loglevel of " << BOOST_PP_STRINGIZE(m) << " set to default 0\n"; \
            } \
        }

#define START_VMODULES(...)           BOOST_PP_SEQ_FOR_EACH(START_VMOD, ,BOOST_PP_VARIADIC_TO_SEQ(__VA_ARGS__))

#define InitOmdsLogging(progname, ...)  \
            google::InitGoogleLogging(progname); \
            START_VMODULES(__VA_ARGS__)

#endif //OMSTORE_LOGGING_HPP
