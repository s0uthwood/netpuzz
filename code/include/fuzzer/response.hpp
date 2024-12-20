#ifndef INCLUDE_FUZZER_RESPONSE_HPP_
#define INCLUDE_FUZZER_RESPONSE_HPP_

#include <regex>
#include <string>
#include <vector>

#include "./defines.hpp"
#include "fuzzer/tcp_connect.hpp"

extern std::string log_dir;

struct Response {
    Response() = default;

    virtual std::string to_string();
    virtual void print();
};

// * Specific class for ipp response
struct IppResponse : Response {
    IppResponse();
    IppResponse(TcpData data);

    ~IppResponse();

    struct Attribute {
        uint8_t tag_id;
        std::string name;
        std::vector<uint8_t> value;
    };

    struct AttributeGroup {
        uint8_t tag_id;
        std::vector<Attribute> attributes;
    };

    double http_version;
    int http_code;
    uint16_t version_number;
    uint16_t status_code;
    uint32_t request_id;
    std::vector<AttributeGroup> attribute_groups;

    std::string to_string() override;

    bool operator==(const IppResponse &other) const;
    bool operator!=(const IppResponse &other) const;
    int read_chunk_len(u8 *http_body);
    void dechunk(TcpData *http_body);
    void parse(TcpData response);
    void parseAttributeGroup(TcpData response);
    void statusMessageFilter();
    bool isDelimiterTag(uint8_t tag_id);
    
    void print() override;
};
double IppDistance(const std::shared_ptr<IppResponse>& seq1, const std::shared_ptr<IppResponse>& seq2);

struct LpdResponse : Response {
    std::vector<u8> data;

    LpdResponse();
    LpdResponse(TcpData data);

    ~LpdResponse();

    bool operator==(const LpdResponse &other) const;
    bool operator!=(const LpdResponse &other) const;

    std::string to_string() override;

    void parse(TcpData response);
    void print() override;
};
double LpdDistance(const std::shared_ptr<LpdResponse>& seq1, const std::shared_ptr<LpdResponse>& seq2);

#endif  // INCLUDE_FUZZER_RESPONSE_HPP_
