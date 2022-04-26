/*
 * Homestore testing binaries shared common definitions, apis and data structures
 * */

#pragma once
const std::string SPDK_ENV_VAR_STRING{"USER_WANT_SPDK"};
const std::string HTTP_SVC_ENV_VAR_STRING{"USER_WANT_HTTP_OFF"};
const std::string CP_WATCHDOG_TIMER_SEC{"USER_SET_CP_WD_TMR_SEC"};          // used in nightly test;
const std::string FLIP_SLOW_PATH_EVERY_NTH{"USER_SET_SLOW_PATH_EVERY_NTH"}; // used in nightly test;
const std::string BLKSTORE_FORMAT_OFF{"USER_WANT_BLKSTORE_FORMAT_OFF"};     // used for debug purpose;

// TODO: start_homestore should be moved here and called by each testing binaries
