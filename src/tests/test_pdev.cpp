/*********************************************************************************
 * Modifications Copyright 2017-2019 eBay Inc.
 *
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *    https://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software distributed
 * under the License is distributed on an "AS IS" BASIS, WITHOUT WARRANTIES OR
 * CONDITIONS OF ANY KIND, either express or implied. See the License for the
 * specific language governing permissions and limitations under the License.
 *
 *********************************************************************************/
#include <chrono>
#include <condition_variable>
#include <cstdint>
#include <filesystem>
#include <fstream>
#include <map>
#include <memory>
#include <mutex>
#include <random>

#include <gtest/gtest.h>
#include <iomgr/io_environment.hpp>
#include <sisl/logging/logging.h>
#include <sisl/options/options.h>

#include "device/chunk.h"

#include "device/device.h"
#include "device/physical_dev.hpp"

using namespace homestore;
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_pdev, iomgr)

SISL_OPTION_GROUP(test_pdev,
                  (num_data_devs, "", "num_data_devs", "number of data devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("3"), "number"),
                  (num_fast_devs, "", "num_fast_devs", "number of fast devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("2"), "number"),
                  (data_dev_size_mb, "", "data_dev_size_mb", "size of each data device in MB",
                   ::cxxopts::value< uint64_t >()->default_value("1024"), "number"),
                  (fast_dev_size_mb, "", "fast_dev_size_mb", "size of each fast device in MB",
                   ::cxxopts::value< uint64_t >()->default_value("100"), "number"),
                  (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"));

std::vector< std::string > g_data_dev_names;
std::vector< std::string > g_fast_dev_names;

static void remove_files(const std::vector< std::string >& file_paths) {
    for (const auto& fpath : file_paths) {
        if (std::filesystem::exists(fpath)) { std::filesystem::remove(fpath); }
    }
}

static void init_file(const std::string& fpath, uint64_t dev_size) {
    if (std::filesystem::exists(fpath)) { std::filesystem::remove(fpath); }
    std::ofstream ofs{fpath, std::ios::binary | std::ios::out | std::ios::trunc};
    std::filesystem::resize_file(fpath, dev_size);
}

class PDevTest : public ::testing::Test {
protected:
    std::unique_ptr< DeviceManager > m_dmgr;
    std::vector< std::string > m_data_dev_names;
    std::vector< std::string > m_fast_dev_names;
    std::vector< homestore::dev_info > m_dev_infos;
    PhysicalDev* m_first_data_pdev{nullptr};
    PhysicalDev* m_first_fast_pdev{nullptr};
    std::vector< shared< Chunk > > m_data_chunks;
    std::vector< shared< Chunk > > m_fast_chunks;

public:
    void setup_device_manager() {
        auto const is_spdk = SISL_OPTIONS["spdk"].as< bool >();

        ioenvironment.with_iomgr(iomgr::iomgr_params{.num_threads = 1, .is_spdk = is_spdk});
        m_dmgr = std::make_unique< homestore::DeviceManager >(
            m_dev_infos, [this](const homestore::vdev_info&, bool load_existing) -> shared< homestore::VirtualDev > {
                return nullptr;
            });
        m_dmgr->is_first_time_boot() ? m_dmgr->format_devices() : m_dmgr->load_devices();
        m_first_data_pdev = m_dmgr->get_pdevs_by_dev_type(homestore::HSDevType::Data)[0];
        m_first_fast_pdev = m_dmgr->get_pdevs_by_dev_type(homestore::HSDevType::Fast)[0];
    }

    void restart() {
        m_first_data_pdev = nullptr;
        m_first_fast_pdev = nullptr;
        m_data_chunks.clear();
        m_fast_chunks.clear();
        m_dmgr.reset();
        iomanager.stop();

        setup_device_manager();
        m_first_data_pdev->load_chunks([this](cshared< Chunk >& chunk) {
            LOGINFO("Loading data chunk details={}", chunk->to_string());
            m_data_chunks.push_back(chunk);
            return true;
        });
        m_first_fast_pdev->load_chunks([this](cshared< Chunk >& chunk) {
            LOGINFO("Loading fast chunk details={}", chunk->to_string());
            m_fast_chunks.push_back(chunk);
            return true;
        });
    }

    virtual void SetUp() override {
        auto const data_ndevices = SISL_OPTIONS["num_data_devs"].as< uint32_t >();
        auto const fast_ndevices = SISL_OPTIONS["num_fast_devs"].as< uint32_t >();
        auto const data_dev_size = SISL_OPTIONS["data_dev_size_mb"].as< uint64_t >() * 1024 * 1024;
        auto const fast_dev_size = SISL_OPTIONS["fast_dev_size_mb"].as< uint64_t >() * 1024 * 1024;

        LOGINFO("creating {} data device files with each of size {} ", data_ndevices,
                homestore::in_bytes(data_dev_size));
        for (uint32_t i{0}; i < data_ndevices; ++i) {
            auto fname = std::string{"/tmp/test_pdev_data_" + std::to_string(i + 1)};
            init_file(fname, data_dev_size);
            m_data_dev_names.emplace_back(fname);
            m_dev_infos.emplace_back(std::filesystem::canonical(fname).string(), homestore::HSDevType::Data);
        }

        LOGINFO("creating {} fast device files with each of size {} ", fast_ndevices,
                homestore::in_bytes(fast_dev_size));
        for (uint32_t i{0}; i < fast_ndevices; ++i) {
            auto fname = std::string{"/tmp/test_pdev_fast_" + std::to_string(i + 1)};
            init_file(fname, fast_dev_size);
            m_fast_dev_names.emplace_back(fname);
            m_dev_infos.emplace_back(std::filesystem::canonical(fname).string(), homestore::HSDevType::Fast);
        }

        setup_device_manager();
    }

    virtual void TearDown() override {
        m_dmgr.reset();
        iomanager.stop();

        remove_files(m_data_dev_names);
        remove_files(m_fast_dev_names);
    }
};

TEST_F(PDevTest, NoChunkRestart) {
    LOGINFO("Restart device manager");
    restart();
}

TEST_F(PDevTest, OrderlyChunkOpsWithRestart) {
    auto const data_pdev_size = m_first_data_pdev->data_size();
    LOGINFO("Step 1: Creating 4 data pdev chunks in one shot each of size={}", homestore::in_bytes(data_pdev_size / 6));
    std::vector< uint32_t > data_chunk_ids{0, 1, 2, 3};
    m_data_chunks = m_first_data_pdev->create_chunks(data_chunk_ids, 0u, data_pdev_size / 6);

    LOGINFO("Step 2: Creating 4 data pdev chunks independetly of smaller size={}",
            homestore::in_bytes(data_pdev_size / 12));
    m_data_chunks.push_back(m_first_data_pdev->create_chunk(4u, 0u, data_pdev_size / 12, 4u));
    m_data_chunks.push_back(m_first_data_pdev->create_chunk(5u, 0u, data_pdev_size / 12, 5u));
    m_data_chunks.push_back(m_first_data_pdev->create_chunk(6u, 0u, data_pdev_size / 12, 6u));
    m_data_chunks.push_back(m_first_data_pdev->create_chunk(7u, 0u, data_pdev_size / 12, 7u));

    auto const fast_pdev_size = m_first_fast_pdev->data_size();
    LOGINFO("Step 3: Creating 4 fast pdev chunks in one shot each of size={}", homestore::in_bytes(fast_pdev_size / 6));
    std::vector< uint32_t > fast_chunk_ids{8, 9, 10, 11};
    m_fast_chunks = m_first_fast_pdev->create_chunks(fast_chunk_ids, 1u, fast_pdev_size / 6);

    LOGINFO("Step 4: Creating 4 fast pdev chunks independently of smaller size={}",
            homestore::in_bytes(fast_pdev_size / 12));
    m_fast_chunks.push_back(m_first_fast_pdev->create_chunk(12u, 1u, fast_pdev_size / 12, 4u));
    m_fast_chunks.push_back(m_first_fast_pdev->create_chunk(13u, 1u, fast_pdev_size / 12, 5u));
    m_fast_chunks.push_back(m_first_fast_pdev->create_chunk(14u, 1u, fast_pdev_size / 12, 6u));
    m_fast_chunks.push_back(m_first_fast_pdev->create_chunk(15u, 1u, fast_pdev_size / 12, 7u));

    LOGINFO("Step 5: Restart device manager to successfully load the chunks");
    restart();

    LOGINFO("Step 6: Removing a bigger data chunk of size={} and fast chunk of size={}",
            homestore::in_bytes(m_data_chunks[2]->size()), homestore::in_bytes(m_fast_chunks[1]->size()));
    m_first_data_pdev->remove_chunk(std::move(m_data_chunks[2]));
    m_first_fast_pdev->remove_chunk(std::move(m_fast_chunks[1]));

    LOGINFO("Step 7: Restart device manager to successfully load the chunks");
    restart();

    LOGINFO("Step 8: Post restart, create 2 smaller data chunks of size={}, overall size is same as "
            "preremoval",
            homestore::in_bytes(data_pdev_size / 12));
    m_data_chunks.push_back(m_first_data_pdev->create_chunk(16u, 0u, data_pdev_size / 12, 8u));
    m_data_chunks.push_back(m_first_data_pdev->create_chunk(17u, 0u, data_pdev_size / 12, 9u));

    LOGINFO("Step 9: Post restart, create 2 smaller fast chunks of size={}, overall size is same as "
            "preremoval",
            homestore::in_bytes(fast_pdev_size / 12));
    m_fast_chunks.push_back(m_first_fast_pdev->create_chunk(18u, 1u, fast_pdev_size / 12, 8u));
    m_fast_chunks.push_back(m_first_fast_pdev->create_chunk(19u, 1u, fast_pdev_size / 12, 9u));

    LOGINFO("Step 10: Restart device manager to successfully load the chunks");
    restart();
}

TEST_F(PDevTest, RandomChunkOpsWithRestart) {
    static constexpr uint32_t max_iterations = 1000;

    auto const pdev_size = m_first_data_pdev->data_size();

    static thread_local std::random_device rd{};
    static thread_local std::default_random_engine re{rd()};
    std::uniform_int_distribution< uint8_t > op_gen{0, 1};
    std::uniform_int_distribution< uint64_t > size_gen{0, pdev_size - 1};
    std::set< shared< Chunk > > chunks;
    uint32_t chunk_id{0};
    uint32_t ordinal{0};
    uint32_t num_created{0};
    uint32_t num_removed{0};

    uint64_t available_size = pdev_size;
    for (uint32_t iter = 0; iter < max_iterations; ++iter) {
        uint8_t op = op_gen(re);
        if (op == 0) { // Single chunk creation
            if (available_size > 0) {
                auto chunk_size = size_gen(re);
                if (chunk_size > available_size) { chunk_size = available_size; }
                LOGINFO("Creating random sized chunk of size={}", homestore::in_bytes(chunk_size));
                try {
                    chunks.insert(m_first_data_pdev->create_chunk(chunk_id++, 1u, chunk_size, ordinal++));
                    available_size -= chunk_size;
                    ++num_created;
                } catch (std::out_of_range const& e) {
                    LOGINFO("Creating random sized chunk of size={} didn't find suitable space",
                            homestore::in_bytes(chunk_size));
                }
            }
        } else { // Single Chunk Removal
            if (chunks.size() > 0) {
                std::uniform_int_distribution< uint64_t > chunk_index_gen{0, chunks.size() - 1};
                auto idx = chunk_index_gen(re);
                auto it = chunks.begin();
                std::advance(it, idx);

                auto chunk_size = (*it)->size();
                LOGINFO("Removing random sized chunk of size={}", homestore::in_bytes(chunk_size));
                m_first_data_pdev->remove_chunk(*it);
                chunks.erase(it);
                available_size += chunk_size;
                ++num_removed;
            }
        }
    }

    LOGINFO("Test created {} chunks and removed {} chunks successfully, final available size={}", num_created,
            num_removed, available_size);
}

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging, test_pdev, iomgr);
    ::testing::InitGoogleTest(&argc, argv);
    sisl::logging::SetLogger("test_pdev");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
