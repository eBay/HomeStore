#pragma once

#include "crc32.h"
#include "hex_dump.h"
#include "human_readable_number.h"

#include <chrono>
#include <ctime>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <thread>
#include <vector>

#ifdef __linux__
#include <dirent.h>
#include <sys/stat.h>
#include <sys/statvfs.h>
#include <sys/time.h>
#include <sys/types.h>
#include <unistd.h>
#endif

#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic push
#pragma GCC diagnostic ignored "-Wunused-parameter"
#endif
#include <libnuraft/nuraft.hxx>
#if defined __clang__ or defined __GNUC__
#pragma GCC diagnostic pop
#endif

#define DELETE(ptr) \
    delete ptr;     \
    ptr = nullptr   \

#define FREE(ptr)   \
    free(ptr);      \
    ptr = nullptr   \

class GenericTimer {
  public:
    GenericTimer(uint64_t _duration_sec = 0, bool fire_first_event = false)
        : duration_us(_duration_sec * 1000000)
        , firstEventFired(!fire_first_event) {
        reset();
    }

    struct TimeInfo {
        TimeInfo()
            : year(0), month(0), day(0), hour(0), min(0), sec(0)
            , msec(0), usec(0) {}
        TimeInfo(std::chrono::system_clock::time_point now) {
            std::time_t raw_time = std::chrono::system_clock::to_time_t(now);
            std::tm* lt_tm = std::localtime(&raw_time);
            year = lt_tm->tm_year + 1900;
            month = lt_tm->tm_mon + 1;
            day = lt_tm->tm_mday;
            hour = lt_tm->tm_hour;
            min = lt_tm->tm_min;
            sec = lt_tm->tm_sec;

            size_t us_epoch = std::chrono::duration_cast
                              < std::chrono::microseconds >
                              ( now.time_since_epoch() ).count();
            msec = (us_epoch / 1000) % 1000;
            usec = us_epoch % 1000;
        }
        void now() {
            *this = TimeInfo(GenericTimer::now());
        }
        std::string toString() {
            thread_local char time_char[64];
            sprintf(time_char, "%04d-%02d-%02d %02d:%02d:%02d.%03d %03d",
                    year, month, day, hour,
                    min, sec, msec, usec);
            return time_char;
        }
        int year;
        int month;
        int day;
        int hour;
        int min;
        int sec;
        int msec;
        int usec;
    };

    static std::chrono::system_clock::time_point now() {
        return std::chrono::system_clock::now();
    }

    static void sleepUs(size_t us) {
        std::this_thread::sleep_for(std::chrono::microseconds(us));
    }

    static void sleepMs(size_t ms) {
        std::this_thread::sleep_for(std::chrono::milliseconds(ms));
    }

    static void sleepSec(size_t sec) {
        std::this_thread::sleep_for(std::chrono::seconds(sec));
    }

    static inline void getTimeofDay(uint64_t& sec_out, uint32_t& us_out) {
        struct timeval tv;
        gettimeofday(&tv, nullptr);
        sec_out = tv.tv_sec;
        us_out = tv.tv_usec;
    }

    static inline uint64_t getTimeofDay() {
        uint64_t sec_out = 0;
        uint32_t us_out = 0;
        GenericTimer::getTimeofDay(sec_out, us_out);
        return sec_out;
    }

    inline bool timeout() const {
        if (!firstEventFired) {
            // First event, return `true` immediately.
            firstEventFired = true;
            return true;
        }

        auto cur = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed = cur - start;
        return (duration_us < elapsed.count() * 1000000);
    }

    inline bool timeoutAndReset() {
        auto cur = std::chrono::system_clock::now();

        if (!firstEventFired) {
            // First event, return `true` immediately.
            firstEventFired = true;
            return true;
        }

        std::chrono::duration<double> elapsed = cur - start;
        if (duration_us < elapsed.count() * 1000000) {
            start = cur;
            return true;
        }
        return false;
    }

    inline void reset() {
        start = std::chrono::system_clock::now();
    }

    inline uint64_t getElapsedUs() const {
        auto cur = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed = cur - start;
        return elapsed.count() * 1000000;
    }

    inline uint64_t getElapsedMs() const {
        auto cur = std::chrono::system_clock::now();
        std::chrono::duration<double> elapsed = cur - start;
        return elapsed.count() * 1000;
    }

    inline size_t getDurationSec() const {
        return duration_us / 1000000;
    }

    inline void resetDurationUs(uint64_t us) {
        duration_us = us;
        reset();
    }
    inline void resetDurationMs(uint64_t ms) {
        duration_us = ms * 1000;
        reset();
    }

  protected:
    std::chrono::time_point<std::chrono::system_clock> start;
    uint64_t duration_us;
    mutable bool firstEventFired;
};

class PathMgr {
  public:
    static bool exist(const std::string& path) {
        struct stat st;
        if (stat(path.c_str(), &st) != 0) return false;
        return true;
    }
    static int mkdir(const std::string& path) {
        return ::mkdir(path.c_str(), 0755);
    }
    static int rmdir(const std::string& path) {
        if (!exist(path)) return 0;

        std::string cmd = "rm -rf " + path;
        return ::system(cmd.c_str());
    }
    static int remove(const std::string& path) {
        if (!exist(path)) return 0;
        return ::remove(path.c_str());
    }
    static int move(const std::string& from, const std::string& to) {
        if (!exist(from)) return 0;

        std::string cmd = "mv " + from + " " + to;
        return ::system(cmd.c_str());
    }
    static int truncate(const std::string& path, uint64_t size) {
        if (!exist(path)) return 0;
        return ::truncate(path.c_str(), size);
    }
    static int scan(const std::string& path,
                    std::vector<std::string>& files_out) {
        DIR *dir_info = nullptr;
        struct dirent *dir_entry = nullptr;

        dir_info = opendir(path.c_str());
        while ( dir_info && (dir_entry = readdir(dir_info)) ) {
            files_out.push_back(dir_entry->d_name);
        }
        closedir(dir_info);
        return 0;
    }
    static uint64_t dirSize(const std::string& path,
                            bool recursive = false) {
        uint64_t ret = 0;
        DIR *dir_info = nullptr;
        struct dirent *dir_entry = nullptr;

        dir_info = opendir(path.c_str());
        while ( dir_info && (dir_entry = readdir(dir_info)) ) {
            std::string d_name = dir_entry->d_name;
            if (d_name == "." || d_name == "..") continue;

            std::string full_path = path + "/" + d_name;

            if (dir_entry->d_type == DT_REG) {
                struct stat st;
                if (stat(full_path.c_str(), &st) == 0) {
                    ret += st.st_size;
                }

            } else if (recursive && dir_entry->d_type == DT_DIR) {
                ret += dirSize(full_path, recursive);
            }
        }
        closedir(dir_info);
        return ret;
    }
    static std::string getDirPart(const std::string& full_path) {
        size_t pos = full_path.rfind("/");
        if (pos == std::string::npos) return ".";
        return full_path.substr(0, pos);
    }
    static bool isRelPath(const std::string& path) {
        // If start with `./` or `../`: relative path.
        if (path.substr(0, 2) == "./" ||
                path.substr(0, 3) == "../") return true;

        // If filename only: relative path.
        if (path.find("/") == std::string::npos) return true;

        // Otherwise: absolute path.
        return false;
    }
    static void readFile(const std::string& filename, std::string& output) {
        std::ifstream fs;

        fs.open(filename);
        if (!fs.good()) return;

        std::stringstream ss;
        ss << fs.rdbuf();
        fs.close();

        output = ss.str();
    }
    static uint64_t getTotalSpace(const std::string& path) {
        struct statvfs res;
        int rc = statvfs(path.c_str(), &res);
        if (rc != 0) return 0;
        return (uint64_t)res.f_bsize * res.f_blocks;
    }
    static uint64_t getFreeSpace(const std::string& path) {
        struct statvfs res;
        int rc = statvfs(path.c_str(), &res);
        if (rc != 0) return 0;
        return (uint64_t)res.f_bsize * res.f_bavail;
    }
};

class HexDump {
  public:
    static std::string toString(const std::string& str) {
        return toString(str.data(), str.size());
    }

    static std::string toString(const void* pd, size_t len) {
        char* buffer;
        size_t buffer_len;
        print_hex_options opt = PRINT_HEX_OPTIONS_INITIALIZER;
        opt.actual_address = 0;
        opt.enable_colors = 0;
        print_hex_to_buf(&buffer, &buffer_len,
                         pd, len,
                         opt);
        std::string s = std::string(buffer);
        free(buffer);
        return s;
    }

    static std::string rStr(const std::string& str, size_t limit = 16) {
        std::stringstream ss;
        size_t size = std::min(str.size(), limit);
        for (size_t ii=0; ii<size; ++ii) {
            char cc = str[ii];
            if (0x20 <= cc && cc <= 0x7d) {
                ss << cc;
            } else {
                ss << '.';
            }
        }
        ss << " (" << str.size() << ")";
        return ss.str();
    }

    // Convert binary to hex string:
    // {0x01, 0x23, 0xab} -> "0123ab"
    static std::string bin2HexStr(const void* buf, size_t len) {
        std::string hex_str;
        const uint8_t* ptr = static_cast<const uint8_t*>(buf);
        for (size_t ii = 0; ii < len; ++ii) {
            char temp[8];
            sprintf(temp, "%02x", ptr[ii]);
            hex_str += temp;
        }
        return hex_str;
    }

    // Convert hex string to binary:
    // "0123ab" -> {0x01, 0x23, 0xab}
    static std::string hexStr2bin(const std::string& hex_str) {
        std::vector<uint8_t> ret(hex_str.size() / 2, 0);
        uint8_t* ptr = &ret[0];
        for (size_t ii=0; ii<hex_str.size(); ii+=2) {
            std::string cur_hex = hex_str.substr(ii, 2);
            *(ptr + (ii/2)) = std::stoul(cur_hex, nullptr, 16);
        }
        return std::string((const char*)&ret[0], ret.size());
    }
};

class StringHelper {
  public:
    // Replace all `before`s in `src_str` with `after.
    // e.g.) before="a", after="A", src_str="ababa"
    //       result: "AbAbA"
    static std::string replace(const std::string& src_str,
                               const std::string& before,
                               const std::string& after) {
        size_t last = 0;
        size_t pos = src_str.find(before, last);
        std::string ret;
        while (pos != std::string::npos) {
            ret += src_str.substr(last, pos - last);
            ret += after;
            last = pos + before.size();
            pos = src_str.find(before, last);
        }
        if (last < src_str.size()) {
            ret += src_str.substr(last);
        }
        return ret;
    }
};

