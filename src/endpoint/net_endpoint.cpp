//
// Created by Kadayam, Hari on 02/04/18.
//
#if 0
#include "endpoint.hpp"

namespace homeio {
NetEndPoint::NetEndPoint(std::string &server, int port) : EndPoint() {
    if (port == -1) {
        create_unix_connection(server);
    } else {
        create_tcp_connection(server, port);
    }

    // Make the socket a non-blocking one
    EndPoint::set_blocking(m_localfd, false);
    m_evm = nullptr;

    m_closed.store(false);
    // TODO: Change this to false after fixing bug.
    m_write_ready.store(false);
    m_pending_sendq = std::make_shared<evm_buffer_queue<iovec_list>>(512, true, true);

    LOG(INFO)<< "Connected to server=" << server << " port=" << port;
}

void NetEndPoint::create_unix_connection(std::string server) throw () {
    // Usual steps,
    // ****** 1. Create Socket *********
    m_fd = ::socket(AF_UNIX, SOCK_STREAM, 0);
    if (m_fd == -1) {
        LOG(ERROR)<< "Connection to " << server << " failed. Unable to create socket ";
        throw std::invalid_argument("Unable to create socket");
    }

    // ****** 2. Bind Socket *********
    struct sockaddr_un unix_addr;
    memset(&unix_addr, '0', sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;

    // Form a new unix endpoint for local connection.
    std::stringstream ss;
    ss << "/tmp/monstor_local_conn_" << m_localfd;
    m_local_ux_name = ss.str();
    strcpy(unix_addr.sun_path, m_local_ux_name.c_str());

    int ret = ::bind(m_fd, (struct sockaddr*) &unix_addr, sizeof(unix_addr));
    if (ret != 0) {
        LOG(ERROR)<< "Connection to " << server << " failed with errno=" << errno <<
                  " Unable to bind socket to " << m_local_ux_name;
        m_fd = -1;
        throw std::invalid_argument("Bind failed, Invalid end point?");
    }

    // ****** 3. Connect Socket to endpoint *********
    memset(&unix_addr, '0', sizeof(unix_addr));
    unix_addr.sun_family = AF_UNIX;
    strcpy(unix_addr.sun_path, server.c_str());
    ret = ::connect(m_fd, (struct sockaddr *) &unix_addr, sizeof(unix_addr));

    if (ret != 0) {
        LOG(ERROR)<< "Connection to " << server << " failed with errno=" << errno;
        m_fd = -1;
        throw std::invalid_argument("Connection failed, Invalid end point?");
    }
}

void NetEndPoint::create_tcp_connection(std::string server, int port) {
    struct addrinfo hints, *servinfo, *p;
    int rv;

    memset(&hints, 0, sizeof hints);
    hints.ai_family = AF_UNSPEC; // use AF_INET6 to force IPv6
    hints.ai_socktype = SOCK_STREAM;

    if ((rv = getaddrinfo(server.c_str(), std::to_string(port).c_str(), &hints, &servinfo)) != 0) {
        std::string msg("getaddrinfo error: ");
        LOG(ERROR)<< msg << server << ": " << port << ": "<< gai_strerror(rv);
        throw std::runtime_error(msg + gai_strerror(rv));
    }

    for (p = servinfo; p != NULL; p = p->ai_next) {
        if ((m_fd = socket(p->ai_family, p->ai_socktype, p->ai_protocol)) == -1) {
            LOG(WARNING)<< "socket creation error: "<< errno;
            continue;
        }

        rv = ::connect(m_localfd, p->ai_addr, p->ai_addrlen);
        if (rv != 0) {
            LOG(WARNING) << "connect failed: " << errno;
            m_localfd = -1;
            continue;
        }
        break;
    }

    if (p == NULL) {
        // looped off the end of the list with no connection
        LOG(ERROR)<< "Failed to connect!";
        throw std::runtime_error("Failed to connect!");
    }
}

}
#endif
