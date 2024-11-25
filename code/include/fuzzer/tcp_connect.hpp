#ifndef INCLUDE_FUZZER_TCP_CONNECT_HPP_
#define INCLUDE_FUZZER_TCP_CONNECT_HPP_

#include <stdexcept>
#include <string>
#include <vector>

#include "./defines.hpp"

class TCPException : public std::runtime_error {
 public:
    explicit TCPException(const std::string &message) :
        std::runtime_error(message) {
    }
};

class TCPConnectException : public TCPException {
 public:
    explicit TCPConnectException(const std::string &message) :
        TCPException(message) {
    }
};

class TCPTimeoutException : public TCPException {
 public:
    explicit TCPTimeoutException(const std::string &message) :
        TCPException(message) {
    }
};

struct TcpData {
    uint8_t *data_ptr;
    size_t data_len;

    TcpData();
    TcpData(const TcpData &other);
    explicit TcpData(const std::vector<u8> &other);

    ~TcpData();

    TcpData &operator=(const TcpData &other);

    bool operator==(const TcpData &other) const;
    bool operator!=(const TcpData &other) const;

    TcpData &operator+=(const TcpData &other);
    TcpData operator+(const TcpData &other) const;

    // edit data method
    TcpData subdata(size_t start, size_t end);
    int find(const TcpData &pattern);
    int find(const TcpData &pattern, int start_pos);
    int find(const std::string &pattern);
    int find(const std::string &pattern, int start_pos);
    void cut(size_t start, size_t end);

    // debug method
    std::string dataToHex();
};

class TCPConnect {
 private:
    std::string address;
    int port{};
    int socketDescriptor;

 public:
    TCPConnect();
    ~TCPConnect();

    void setAddress(const std::string &address, int port);
    std::string getAddress();
    int getPort();
    void connect();
    void close();
    void send(const uint8_t *message, const size_t message_len, int flags);
    int receive(TcpData* receivedData);
};

#endif  // INCLUDE_FUZZER_TCP_CONNECT_HPP_
