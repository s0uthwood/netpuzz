#ifndef INCLUDE_FUZZER_TEST_CASE_HPP_
#define INCLUDE_FUZZER_TEST_CASE_HPP_

#include <string>
#include <vector>

#include "./defines.hpp"
#include "./xml_extension.hpp"
#include "fuzzer/tcp_connect.hpp"

extern std::string log_dir;

struct PacketData {
    TcpData tcp_data;
    u32 delay_time;

    PacketData();
    PacketData(const TcpData &tcp_data, u32 delay_time);

    ~PacketData();
    std::string dataToHex();
};

struct TestCase {
    std::vector<PacketData> data_list;
    XmlExtension xml_extension;

    TestCase();
    explicit TestCase(const std::string& filename);
    void assembleSequence(const pugi::xml_document &doc);
    void generateFromInputXml();
    void generateFromXml(const std::string& filename);

    std::vector<PacketData> getDataList() const;
    PacketData &getData(size_t index);
    std::string printTestCase();
};

#endif  // INCLUDE_FUZZER_TEST_CASE_HPP_
