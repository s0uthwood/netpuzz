#include "fuzzer/test_case.hpp"

#include <fstream>
#include <iostream>

#include "./utils.hpp"

PacketData::PacketData() {
    tcp_data = TcpData();
    delay_time = 0;
}

PacketData::PacketData(const TcpData &tcp_data, u32 delay_time) {
    // Deep copy
    this->tcp_data = TcpData(tcp_data);
    this->delay_time = delay_time;
}

PacketData::~PacketData() {
    tcp_data.~TcpData();
}

std::string PacketData::dataToHex() {
    std::string result;
    for (size_t i = 0; i < tcp_data.data_len; i++) {
        char buffer[16] = {0};
        snprintf(buffer, sizeof(buffer), "%02x", tcp_data.data_ptr[i]);
        result += buffer;
        if (i != tcp_data.data_len - 1) {
            result += " ";
        }
    }
    return result;
}

void PacketData::debugPrint() {
    printf("Data: ");
    for (size_t i = 0; i < tcp_data.data_len; i++) {
        printf("%02x ", tcp_data.data_ptr[i]);
    }
    printf("\n");
    printf("Delay (ms): %u\n", delay_time);
}

TestCase::TestCase() {
    data_list.clear();
}

TestCase::TestCase(const std::string& filename) {
    data_list.clear();
    generateFromXml(filename);
}

void TestCase::assembleSequence(const pugi::xml_document &doc) {
    pugi::xml_node sequence = doc.child("Sequence");
    if (!sequence) {
        throw std::runtime_error("Error: Sequence node not found");
    }
    PacketData newData;
    for (pugi::xml_node packet = sequence.child("Packet"); packet; packet = packet.next_sibling("Packet")) {
        std::string delay_str = packet.attribute("delay").as_string();
        // delay_str may have space
        u64 delay = parseHexStringAsLittleEndian(delay_str, (delay_str.length() + 1) / 3);
        // int delay = packet.attribute("delay").as_int();
        newData.delay_time = static_cast<u32>(delay) + packet.attribute("diff").as_int();
        if (newData.delay_time > MAX_DELAY) {
            newData.delay_time = MAX_DELAY;
        } else if (newData.delay_time < MIN_DELAY) {
            newData.delay_time = MIN_DELAY;
        }
        for (pugi::xml_node data : packet) {
            std::vector<u8> buffer;
            xml_extension.assembleNodes(data, buffer);
            newData.tcp_data += TcpData(buffer);
        }
        data_list.push_back(newData);
        if (newData.tcp_data.data_ptr) {
            free(newData.tcp_data.data_ptr);
            newData.tcp_data.data_ptr = nullptr;
            newData.tcp_data.data_len = 0;
        }
        // newData.tcp_data.~TcpData();
    }
}

void TestCase::generateFromInputXml() {
    generateFromXml(::log_dir + INPUT_FILE_NAME);
}

void TestCase::generateFromXml(const std::string& filename) {
    pugi::xml_document doc = pugi::xml_document();
    pugi::xml_parse_result result = doc.load_file(filename.c_str());

    if (!result) {
        throw std::runtime_error("Error: " + std::string(result.description()));
    }

    assembleSequence(doc);
}

std::vector<PacketData> TestCase::getDataList() const {
    return data_list;
}

PacketData &TestCase::getData(size_t index) {
    return data_list[index];
}

std::string TestCase::printTestCase() {
    std::string result;
    for (size_t i = 0; i < data_list.size(); i++) {
        result += "Data " + std::to_string(i) + ": ";
        for (size_t j = 0; j < data_list[i].tcp_data.data_len; j++) {
            result += std::to_string(data_list[i].tcp_data.data_ptr[j]) + " ";
        }
        result += "\n";
    }
    return result;
}

void TestCase::debugPrint() {
    for (size_t i = 0; i < data_list.size(); i++) {
        data_list[i].debugPrint();
    }
}
