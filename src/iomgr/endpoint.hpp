//
// Created by Kadayam, Hari on 02/04/18.
//

#ifndef HOMESTORE_FD_HPP
#define HOMESTORE_FD_HPP
#include <fcntl.h>
#include <unistd.h>
#include <string>

namespace homeio {
class EndPoint {
public:
    EndPoint() : m_fd(-1) {}
    int get_fd() {return m_fd;}

    static bool set_blocking(int fd, bool blocking) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            return false;
        }

        flags = blocking ? (flags & ~O_NONBLOCK) : (flags | O_NONBLOCK);
        return (fcntl(fd, F_SETFL, flags) == 0) ? true : false;
    }

    static bool is_blocking(int fd) {
        int flags = fcntl(fd, F_GETFL, 0);
        if (flags < 0) {
            return false;
        }
        return !(flags & O_NONBLOCK);
    }

protected:
    int m_fd;
};

class DriveEndPoint : public EndPoint {
public:
    DriveEndPoint(std::string devname, int oflags);
    int get_sync_fd() {
        return m_sync_fd;
    }

    void sync_write(const char *data, uint32_t size, uint64_t offset);
    void sync_writev(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);
    void sync_read(char *data, uint32_t size, uint64_t offset);
    void sync_readv(const struct iovec *iov, int iovcnt, uint32_t size, uint64_t offset);

private:
    int m_sync_fd;
};

class NetEndPoint : public EndPoint {
public:
    NetEndPoint(std::string &server, int port);
    void create_unix_connection(std::string server);
};

class CtrlEndPoint : public EndPoint {
};

}
#endif //HOMESTORE_FD_HPP
