#include "fuzzer/tcp_connect.hpp"

#include <arpa/inet.h>
#include <fcntl.h>
#include <netinet/tcp.h>
#include <sys/socket.h>
#include <unistd.h>

#include <cerrno>
#include <cstring>
#include <iostream>

TcpData::TcpData() {
    data_len = 0;
    data_ptr = nullptr;
}

TcpData::TcpData(const TcpData &other) {
    data_len = other.data_len;
    if (data_len > 0) {
        data_ptr = static_cast<uint8_t *>(malloc(data_len));
        memcpy(data_ptr, other.data_ptr, data_len);
    } else {
        data_ptr = nullptr;
    }
}

TcpData::TcpData(const std::vector<u8> &other) {
    data_len = other.size();
    if (data_len > 0) {
        data_ptr = static_cast<uint8_t *>(malloc(data_len));
        memcpy(data_ptr, other.data(), data_len);
    } else {
        data_ptr = nullptr;
    }
}

TcpData::~TcpData() {
    if (data_ptr) {
        free(data_ptr);
        data_ptr = nullptr;
        data_len = 0;
    }
}

TcpData &TcpData::operator=(const TcpData &other) {
    if (this == &other) {
        return *this;
    }
    data_len = other.data_len;
    if (data_ptr) {
        free(data_ptr);
        data_ptr = nullptr;
    }
    data_ptr = static_cast<uint8_t *>(malloc(data_len));
    memcpy(data_ptr, other.data_ptr, data_len);
    return *this;
}

bool TcpData::operator==(const TcpData &other) const {
    if (data_len != other.data_len) {
        return false;
    }
    for (size_t i = 0; i < data_len; i++) {
        if (data_ptr[i] != other.data_ptr[i]) {
            return false;
        }
    }
    return true;
}

bool TcpData::operator!=(const TcpData &other) const {
    return !(*this == other);
}

TcpData &TcpData::operator+=(const TcpData &other) {
    if (data_len == 0) {
        if (data_ptr) {
            free(data_ptr);
            data_ptr = nullptr;
        }
        data_len = other.data_len;
        if (data_len > 0) {
            data_ptr = static_cast<u8 *>(malloc(data_len));
            if (!data_ptr) {
                throw std::runtime_error("Memory allocation failed.");
            }

            memcpy(data_ptr, other.data_ptr, data_len);
        }
    } else if (other.data_len != 0) {
        auto *new_data = static_cast<u8 *>(malloc(data_len + other.data_len));

        if (!new_data) {
            throw std::runtime_error("Memory allocation failed.");
        }

        memcpy(new_data, data_ptr, data_len);
        memcpy(new_data + data_len, other.data_ptr, other.data_len);
        data_len += other.data_len;
        if (data_ptr) {
            free(data_ptr);
        }
        data_ptr = new_data;
    }
    return *this;
}

TcpData TcpData::operator+(const TcpData &other) const {
    TcpData result = *this;
    result += other;
    return result;
}

TcpData TcpData::subdata(size_t start, size_t end) {
    if (start >= end || start >= data_len || end > data_len)
        return {};
    TcpData result;
    result.data_len = end - start;
    result.data_ptr = static_cast<uint8_t *>(malloc(result.data_len));
    memcpy(result.data_ptr, data_ptr + start, result.data_len);
    return result;
}

int TcpData::find(const TcpData &pattern) {
    if (pattern.data_len == 0 || data_len == 0 || pattern.data_len > data_len)
        return -1;
    for (size_t i = 0; i <= data_len - pattern.data_len; ++i) {
        bool found = true;
        for (size_t j = 0; j < pattern.data_len; j++) {
            if (data_ptr[i + j] != pattern.data_ptr[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return i;
        }
    }
    return -1;
}

int TcpData::find(const TcpData &pattern, int start_pos) {
    if (start_pos < 0 || start_pos >= data_len) {
        // throw std::out_of_range("Start position is out of range");
        return -1;
    }
    if (pattern.data_len > (data_len - start_pos)) {
        return -1;  // Pattern is longer than the remaining data, can't find it
    }

    for (int i = start_pos; i <= data_len - pattern.data_len; ++i) {
        bool found = true;
        for (int j = 0; j < pattern.data_len; ++j) {
            if (data_ptr[i + j] != pattern.data_ptr[j]) {
                found = false;
                break;
            }
        }
        if (found) {
            return i;  // Pattern found, return the starting position
        }
    }

    return -1;  // Pattern not found
}

int TcpData::find(const std::string &pattern) {
    TcpData patternData;
    patternData.data_len = pattern.size();
    patternData.data_ptr = static_cast<uint8_t *>(malloc(patternData.data_len));
    memcpy(patternData.data_ptr, pattern.c_str(), patternData.data_len);
    return find(patternData);
}

int TcpData::find(const std::string &pattern, int start_pos) {
    TcpData patternData;
    patternData.data_len = pattern.size();
    patternData.data_ptr = static_cast<uint8_t *>(malloc(patternData.data_len));
    memcpy(patternData.data_ptr, pattern.c_str(), patternData.data_len);
    return find(patternData, start_pos);
}

void TcpData::cut(size_t start, size_t end) {
    if (start >= end || start >= data_len || end > data_len) {
        return;
    }
    if (end - start >= data_len) {
        data_len = 0;
        free(data_ptr);
        data_ptr = nullptr;
        return;
    }
    size_t len_move = data_len - end;
    data_len -= end - start;
    std::memmove(data_ptr + start, data_ptr + end, len_move);
    auto *tmp = reinterpret_cast<uint8_t *>(realloc(data_ptr, data_len));
    if (tmp) {
        data_ptr = tmp;
    }
}

std::string TcpData::dataToHex() {
    std::string result;
    for (size_t i = 0; i < data_len; i++) {
        char buffer[16] = {0};
        snprintf(buffer, sizeof(buffer), "%02x", data_ptr[i]);
        result += buffer;
        if (i != data_len - 1) {
            result += " ";
        }
    }
    return result;
}

TCPConnect::TCPConnect(/* args */) {
    socketDescriptor = -1;
    port = 0;
}

TCPConnect::~TCPConnect() {
    if (socketDescriptor != -1) {
        ::close(socketDescriptor);
    }
}

void TCPConnect::setAddress(const std::string &address, int port) {
    this->address = address;
    this->port = port;
}

std::string TCPConnect::getAddress() {
    return this->address;
}

int TCPConnect::getPort() {
    return this->port;
}

void TCPConnect::connect() {
    // open a socket
    socketDescriptor = socket(AF_INET, SOCK_STREAM, 0);
    if (socketDescriptor == -1) {
        throw TCPConnectException("Could not create socket.");
    }

    sockaddr_in targetAddress{};
    targetAddress.sin_family = AF_INET;
    targetAddress.sin_port = htons(this->port);
    if (inet_pton(AF_INET, this->address.c_str(), &targetAddress.sin_addr) <= 0) {
        throw TCPConnectException("Invalid address.");
    }

    // set to non-blocking mode
    int flags = fcntl(socketDescriptor, F_GETFL, 0);
    fcntl(socketDescriptor, F_SETFL, flags | O_NONBLOCK);

    if (::connect(socketDescriptor, reinterpret_cast<sockaddr *>(&targetAddress), sizeof(targetAddress)) < 0) {
        // If not in progress, throw an exception
        if (errno != EINPROGRESS) {
            throw TCPConnectException("Could not connect.");
        }
    }

    fd_set fdset;
    FD_ZERO(&fdset);                   // Clears an fd_set
    FD_SET(socketDescriptor, &fdset);  // Adds a socket to an fd_set

    struct timeval tv{};
    tv.tv_sec = 5;
    tv.tv_usec = 0;

    // It waits for the descriptor to become ready
    if (select(socketDescriptor + 1, nullptr, &fdset, nullptr, &tv) == 1) {
        int so_error;
        socklen_t len = sizeof so_error;

        // Getting info in protocol level
        getsockopt(socketDescriptor, SOL_SOCKET, SO_ERROR, &so_error, &len);

        // If error throw an exception
        if (so_error != 0) {
            throw TCPConnectException("Could not connect.");
        }
    } else {
        throw TCPConnectException("Connection timeout.");
    }

    // Setting the descriptor back to blocking mode
    fcntl(socketDescriptor, F_SETFL, flags);

    // Setting a socket timeout
    struct timeval timeout{};
    timeout.tv_sec = 3;
    timeout.tv_usec = 0;
    if (setsockopt(socketDescriptor, SOL_SOCKET, SO_RCVTIMEO, reinterpret_cast<char *>(&timeout), sizeof(timeout)) < 0) {
        throw TCPConnectException("Could not set socket timeout.");
    }

    int optval = 1;
    // Setting TCP_NODELAY option
    if (setsockopt(socketDescriptor, IPPROTO_TCP, TCP_NODELAY, &optval, sizeof(optval)) == -1) {
        throw TCPConnectException("Could not set TCP_NODELAY option.");
    }
}

void TCPConnect::close() {
    if (socketDescriptor != -1) {
        ::close(socketDescriptor);
        socketDescriptor = -1;
    }
}

void TCPConnect::send(const uint8_t *message, const size_t message_len, int flags = 0) {
    if (socketDescriptor == -1) {
        throw TCPConnectException("Not connected to a server.");
    }
    flags |= MSG_NOSIGNAL;
    for (size_t i = 0; i < message_len; i += 1448) {
        if (::send(socketDescriptor, message + i, std::min(message_len - i, static_cast<size_t>(1448)), flags) < 0) {
            // throw TCPConnectException("Could not send message.");
            printf("Could not send message.\n");
            return;
        }
    }
}

int TCPConnect::receive(TcpData *receivedData) {
    if (socketDescriptor == -1) {
        throw TCPConnectException("Not connected to a server.");
    }
    char buffer[4096];
    memset(buffer, 0, sizeof(buffer));
    int valread = ::recv(socketDescriptor, buffer, sizeof(buffer) - 1, 0);
    if (valread > 0) {
        receivedData->data_len = valread;
        if (receivedData->data_ptr) {
            free(receivedData->data_ptr);
        }
        receivedData->data_ptr = static_cast<uint8_t *>(malloc(receivedData->data_len));
        memcpy(receivedData->data_ptr, buffer, receivedData->data_len);
        return true;
    }
    if (valread < 0) {
        if (errno == EAGAIN || errno == EWOULDBLOCK) {
            // throw TCPTimeoutException("Timeout.");
            // throw TCPConnectException("Timeout.");
            std::cout << "Timeout." << std::endl;
        } else {
            // throw TCPConnectException("Could not receive message.");
            std::cout << "Could not receive message." << std::endl;
        }
    }
    if (valread == 0) {
        // throw TCPConnectException("Connection closed.");
        std::cout << "Connection closed." << std::endl;
    }
    // TcpData data;
    if (receivedData->data_ptr) {
        free(receivedData->data_ptr);
    }
    receivedData->data_len = 0;
    receivedData->data_ptr = nullptr;
    return valread;
}
