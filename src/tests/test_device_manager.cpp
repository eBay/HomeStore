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
#include "device/virtual_dev.hpp"

using namespace homestore;
SISL_LOGGING_INIT(HOMESTORE_LOG_MODS)
SISL_OPTIONS_ENABLE(logging, test_device_manager, iomgr)

SISL_OPTION_GROUP(test_device_manager,
                  (num_data_devs, "", "num_data_devs", "number of data devices to create",
                   ::cxxopts::value< uint32_t >()->default_value("3"), "number"),
                  (data_dev_size_mb, "", "data_dev_size_mb", "size of each data device in MB",
                   ::cxxopts::value< uint64_t >()->default_value("1024"), "number"),
                  (spdk, "", "spdk", "spdk", ::cxxopts::value< bool >()->default_value("false"), "true or false"));

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

class DeviceMgrTest : public ::testing::Test {
protected:
    std::unique_ptr< DeviceManager > m_dmgr;
    std::vector< std::string > m_data_dev_names;
    std::vector< homestore::dev_info > m_dev_infos;
    std::vector< PhysicalDev* > m_pdevs;
    std::vector< shared< VirtualDev > > m_vdevs;

public:
    void setup_device_manager() {
        auto const is_spdk = SISL_OPTIONS["spdk"].as< bool >();

        ioenvironment.with_iomgr(iomgr::iomgr_params{.num_threads = 1, .is_spdk = is_spdk});
        m_dmgr = std::make_unique< homestore::DeviceManager >(
            m_dev_infos, [this](const homestore::vdev_info& vinfo, bool load_existing) {
                vdev_info vinfo_tmp = vinfo;
                vinfo_tmp.alloc_type = s_cast< uint8_t >(homestore::blk_allocator_type_t::fixed);
                vinfo_tmp.chunk_sel_type = s_cast< uint8_t >(homestore::chunk_selector_type_t::ROUND_ROBIN);

                return std::make_shared< homestore::VirtualDev >(*m_dmgr, vinfo_tmp, nullptr /* event_cb */, false);
            });
        m_dmgr->is_first_time_boot() ? m_dmgr->format_devices() : m_dmgr->load_devices();
        m_pdevs = m_dmgr->get_pdevs_by_dev_type(homestore::HSDevType::Data);
    }

    void restart() {
        m_dmgr.reset();
        iomanager.stop();

        setup_device_manager();
    }

    virtual void SetUp() override {
        auto const data_ndevices = SISL_OPTIONS["num_data_devs"].as< uint32_t >();
        auto const data_dev_size = SISL_OPTIONS["data_dev_size_mb"].as< uint64_t >() * 1024 * 1024;

        LOGINFO("creating {} data device files with each of size {} ", data_ndevices,
                homestore::in_bytes(data_dev_size));
        for (uint32_t i{0}; i < data_ndevices; ++i) {
            auto fname = std::string{"/tmp/test_devmgr_data_" + std::to_string(i + 1)};
            init_file(fname, data_dev_size);
            m_data_dev_names.emplace_back(fname);
            m_dev_infos.emplace_back(std::filesystem::canonical(fname).string(), homestore::HSDevType::Data);
        }

        setup_device_manager();
    }

    virtual void TearDown() override {
        m_dmgr.reset();
        iomanager.stop();

        remove_files(m_data_dev_names);
    }

    void validate_striped_vdevs() {
        for (auto& vdev : m_vdevs) {
            auto chunks = vdev->get_chunks();
            ASSERT_EQ(chunks.size(), m_pdevs.size() * 2) << "Expected vdev to be created with 2 chunks per pdev";
            auto size = chunks[0]->size();

            std::map< const PhysicalDev*, uint32_t > chunks_in_pdev_count;
            for (const auto& chunk : chunks) {
                ASSERT_EQ(chunk->size(), size) << "All chunks are not equally sized in vdev";

                auto [it, inserted] = chunks_in_pdev_count.insert(std::pair(chunk->physical_dev(), 1u));
                if (!inserted) { ++(it->second); }
            }

            for (const auto& [pdev, count] : chunks_in_pdev_count) {
                ASSERT_EQ(count, 2) << "Every pdev should have exactly 2 chunks, that has not happened here";
            }
        }
    }
};

TEST_F(DeviceMgrTest, StripedVDevCreation) {
    static constexpr uint32_t num_test_vdevs = 5;
    uint64_t avail_size{0};
    for (auto& pdev : m_pdevs) {
        avail_size += pdev->data_size();
    }

    uint32_t size_pct = 2;
    uint64_t remain_size = avail_size;

    LOGINFO("Step 1: Creating {} vdevs with combined size as {}", num_test_vdevs, in_bytes(avail_size));
    for (uint32_t i = 0; i < num_test_vdevs; ++i) {
        std::string name = "test_vdev_" + std::to_string(i + 1);
        uint64_t size = std::min(remain_size, (avail_size * size_pct) / 100);
        remain_size -= size;
        size_pct *= 2; // Double the next vdev size

        LOGINFO("Step 1a: Creating vdev of name={} with size={}", name, in_bytes(size));
        auto vdev =
            m_dmgr->create_vdev(homestore::vdev_parameters{.vdev_name = name,
                                                           .vdev_size = size,
                                                           .num_chunks = uint32_cast(m_pdevs.size() * 2),
                                                           .blk_size = 4096,
                                                           .dev_type = HSDevType::Data,
                                                           .alloc_type = blk_allocator_type_t::none,
                                                           .chunk_sel_type = chunk_selector_type_t::NONE,
                                                           .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                           .context_data = sisl::blob{}});
        m_vdevs.push_back(std::move(vdev));
    }

    LOGINFO("Step 2: Validating all vdevs if they have created with correct number of chunks");
    this->validate_striped_vdevs();

    LOGINFO("Step 3: Restarting homestore");
    this->restart();

    LOGINFO("Step 4: Post Restart validate if all vdevs are loaded with correct number of chunks");
    this->validate_striped_vdevs();
}

TEST_F(DeviceMgrTest, CreateChunk) {
    // Create dynamically chunks and verify no two chunks ahve same start offset.
    uint64_t avail_size{0};
    for (auto& pdev : m_pdevs) {
        avail_size += pdev->data_size();
    }

    LOGINFO("Step 1: Creating test_vdev with size={}", in_bytes(avail_size));
    auto vdev =
        m_dmgr->create_vdev(homestore::vdev_parameters{.vdev_name = "test_vdev",
                                                       .size_type = vdev_size_type_t::VDEV_SIZE_DYNAMIC,
                                                       .vdev_size = avail_size,
                                                       .num_chunks = 0,
                                                       .blk_size = 512,
                                                       .chunk_size = 512 * 1024,
                                                       .dev_type = HSDevType::Data,
                                                       .alloc_type = blk_allocator_type_t::none,
                                                       .chunk_sel_type = chunk_selector_type_t::NONE,
                                                       .multi_pdev_opts = vdev_multi_pdev_opts_t::ALL_PDEV_STRIPED,
                                                       .context_data = sisl::blob{}});

    auto num_chunks = 10;
    LOGINFO("Step 2: Creating {} chunks", num_chunks);
    std::unordered_map< uint32_t, chunk_info > chunk_info_map;
    std::unordered_set< uint64_t > chunk_start;

    for (int i = 0; i < num_chunks; i++) {
        auto chunk = m_dmgr->create_chunk(HSDevType::Data, vdev->info().vdev_id, 512 * 1024, {});
        chunk_info_map[chunk->chunk_id()] = chunk->info();
        auto [_, inserted] = chunk_start.insert(chunk->info().chunk_start_offset);
        ASSERT_EQ(inserted, true) << "chunk start duplicate " << chunk->info().chunk_start_offset;
    }

    LOGINFO("Step 3: Restarting homestore");
    this->restart();

    LOGINFO("Step 4: Creating additional {} chunks", num_chunks);
    for (int i = 0; i < num_chunks; i++) {
        auto chunk = m_dmgr->create_chunk(HSDevType::Data, vdev->info().vdev_id, 512 * 1024, {});
        chunk_info_map[chunk->chunk_id()] = chunk->info();
        auto [_, inserted] = chunk_start.insert(chunk->info().chunk_start_offset);
        ASSERT_EQ(inserted, true) << "chunk start duplicate " << chunk->info().chunk_start_offset;
    }

    chunk_start.clear();
    auto chunk_vec = m_dmgr->get_chunks();
    ASSERT_EQ(chunk_vec.size(), num_chunks * 2);
    for (const auto& chunk : chunk_vec) {
        ASSERT_EQ(chunk->info().chunk_start_offset, chunk_info_map[chunk->chunk_id()].chunk_start_offset)
            << "Chunk offsets mismatch";
        auto [_, inserted] = chunk_start.insert(chunk->info().chunk_start_offset);
        ASSERT_EQ(inserted, true) << "chunk start duplicate " << chunk->info().chunk_start_offset;
    }
    vdev.reset();
}

int main(int argc, char* argv[]) {
    SISL_OPTIONS_LOAD(argc, argv, logging, test_device_manager, iomgr);
    ::testing::InitGoogleTest(&argc, argv);
    sisl::logging::SetLogger("test_device_manager");
    spdlog::set_pattern("[%D %T%z] [%^%l%$] [%n] [%t] %v");

    return RUN_ALL_TESTS();
}
