#include <boost/uuid/random_generator.hpp>
#include <boost/uuid/uuid_io.hpp>
#include <condition_variable>
#include <mutex>

/* Facility headers */
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

/* IOPath */
#include <homestore/homestore.hpp>
#include <iomgr/io_environment.hpp>

SISL_OPTION_GROUP(test_hs_vol,
                  (capacity, "", "capacity", "Size of volume",
                   cxxopts::value<uint32_t>()->default_value("2"), "GiB"),
                  (io_threads, "", "io_threads", "Number of IO threads",
                   cxxopts::value<uint32_t>()->default_value("1"), "count"),
                  (name, "", "name", "Volume name",
                   cxxopts::value<std::string>()->default_value("volume"), ""),
                  (addr, "", "addr", "Do IO on a PCIe address",
                   cxxopts::value<std::string>(), "0000:02:00.0"))

#define ENABLED_OPTIONS logging, iomgr, test_hs_vol, config
#define SPDK_LOG_MODS HOMESTORE_LOG_MODS

SISL_OPTIONS_ENABLE(ENABLED_OPTIONS)
SISL_LOGGING_INIT(SPDK_LOG_MODS)

constexpr size_t Ki = 1024;
constexpr size_t Mi = Ki * Ki;
constexpr size_t Gi = Ki * Mi;

static void init_homestore(std::string const& device_address) {
    // TODO (bszmyd): Need to reimplement without VolAPI
}

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, ENABLED_OPTIONS)
    sisl::logging::SetLogger("spdk_volume");
    sisl::logging::install_crash_handler();
    spdlog::set_pattern("[%D %T.%e] [%^%l%$] [%t] %v");

    // Configure backend BDev
    std::string device_address;
    if (0 < SISL_OPTIONS.count("addr")) {
        device_address = std::string(
            fmt::format("traddr={}", SISL_OPTIONS["addr"].as<std::string>()));
        LOGINFO("Binding device [{}] to SPDK NVMe-BDEV.", device_address);
    } else {
        LOGERROR("Please use --addr in the argument list.");
        return -1;
    }

    // Start the IOManager
    ioenvironment.with_iomgr(SISL_OPTIONS["io_threads"].as<uint32_t>(), true);

    iomanager.stop();
    LOGINFO("Done.");
    return 0;
}
