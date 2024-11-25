#ifndef INCLUDE_FUZZER_TEST_CASE_HPP_
#define INCLUDE_FUZZER_TEST_CASE_HPP_

#include <string>
#include <vector>

#include "./defines.hpp"
#include "./xml_extension.hpp"
#include "fuzzer/tcp_connect.hpp"

extern std::string log_dir;

// Sended data in a packet
struct PacketData {
    TcpData tcp_data;
    // delay_time should be in ms
    u32 delay_time;

    PacketData();
    PacketData(const TcpData &tcp_data, u32 delay_time);

    ~PacketData();
    // send_data();
    std::string dataToHex();
    void debugPrint();
};

// testcase is all the data in a sequence
// use to assemble the data from input.xml
struct TestCase {
    std::vector<PacketData> data_list;
    XmlExtension xml_extension;

    TestCase();
    explicit TestCase(const std::string& filename);
    // NOTE: append data into DataList
    void assembleSequence(const pugi::xml_document &doc);
    void generateFromInputXml();
    void generateFromXml(const std::string& filename);

    std::vector<PacketData> getDataList() const;
    PacketData &getData(size_t index);
    std::string printTestCase();
    void debugPrint();
};

#endif  // INCLUDE_FUZZER_TEST_CASE_HPP_
