#include "fuzzer/response.hpp"

#include <algorithm>
#include <iomanip>
#include <iostream>
#include <sstream>

#include "./utils.hpp"

std::string Response::to_string() {
    return "";
}

void Response::print() {
}

IppResponse::IppResponse() {
    http_version = 0.0;
    http_code = 0;
    version_number = 0;
    status_code = 0xeeee;
    request_id = 0;
    attribute_groups.clear();
}

IppResponse::IppResponse(TcpData data) {
    http_version = 0.0;
    http_code = 0;
    version_number = 0;
    status_code = 0xeeee;
    request_id = 0;
    attribute_groups.clear();
    // std::cout << data.dataToHex() << std::endl;
    parse(data);
}

IppResponse::~IppResponse() {
    for (auto group : attribute_groups) {
        for (auto attr : group.attributes) {
            attr.value.clear();
        }
        group.attributes.clear();
    }
    attribute_groups.clear();
}

int IppResponse::read_chunk_len(u8 *http_body) {
    char *endptr;
    int result = strtol((char *)http_body, &endptr, 16);
    // if number not followed by 0d, it is not chunk format
    if (endptr != (char *)http_body) {
        if (*endptr != '\x0d' || *(endptr + 1) != '\x0a') {
            return -1;
        }
    }
    return result;
}

void IppResponse::dechunk(TcpData *http_body) {
    TcpData result;
    int i = 0;
    while (http_body->data_len > 0) {
        int cur_chunk_len = read_chunk_len(&(http_body->data_ptr[i]));
        // if return -1, is not chunk format
        if (cur_chunk_len == -1) {
            return;
        }
        printf("chunk_len: %d\n", cur_chunk_len);
        int end_index = http_body->find("\r\n", i);
        http_body->cut(i, end_index + 2);
        i += cur_chunk_len;
        // cut 0d0a
        http_body->cut(i, i + 2);
        if (cur_chunk_len == 0) {
            break;
        }
    }
}

void IppResponse::parse(TcpData response) {
    // NOTE: parse HTTP version and status code
    printf("[Debug] before parse\n");
    std::cout << response.dataToHex() << std::endl;
    while (response.find("HTTP") != -1) {
        int cut_size = 4;
        int end_index = response.find("\r\n\r\n");
        if (end_index == -1) {
            end_index = response.find("\r\n");
            cut_size = 2;
        }
        std::regex version_regex(R"(\d\.\d)");
        std::regex status_regex(R"(\d{3})");
        std::smatch regex_res;
        std::string http_header(reinterpret_cast<char *>(response.data_ptr), end_index);
        if (std::regex_search(http_header, regex_res, version_regex)) {
            http_version = atof(regex_res[0].str().c_str());
        }
        if (std::regex_search(http_header, regex_res, status_regex)) {
            http_code = atoi(regex_res[0].str().c_str());
        }
        response.cut(0, end_index + cut_size);
        if (!response.data_ptr) {
            return;
        }
        if (response.data_ptr[0] == '4' && response.data_ptr[1] == '0' && response.data_ptr[2] == '0') {
            http_code = 400;
            return;
        }
    }
    if (response.data_len == 0) {
        return;
    }
    if (response.data_len < 2 || http_code != 200) {
        return;
    }
    u8 first_char = response.data_ptr[0];
    if ((first_char >= 0x30 && first_char <= 0x39) || (first_char >= 0x41 && first_char <= 0x46) || (first_char >= 0x61 && first_char <= 0x66)) {
        // dechunk
        dechunk(&response);
    }
    printf("[After dechunk] %s\n", response.dataToHex().c_str());
    // NOTE: parse ipp parts
    // * ipp version number
    version_number = response.data_ptr[0] << 8 | response.data_ptr[1];
    response.cut(0, 2);
    // * ipp status code
    if (response.data_len < 2) {
        return;
    }
    status_code = response.data_ptr[0] << 8 | response.data_ptr[1];
    response.cut(0, 2);

    // * ipp request id
    if (response.data_len < 4) {
        return;
    }
    request_id = response.data_ptr[0] << 24 | response.data_ptr[1] << 16 | response.data_ptr[2] << 8 | response.data_ptr[3];
    response.cut(0, 4);
    parseAttributeGroup(response);
    // delete extra message in status-message
    statusMessageFilter();
    return;
}

void IppResponse::parseAttributeGroup(TcpData response) {
    if (response.data_len == 0)
        return;
    while (true) {
        AttributeGroup tmp;
        if (response.data_len < 1) {
            return;
        }
        tmp.tag_id = response.data_ptr[0];
        // * end of attribute tag
        if (tmp.tag_id == 0x3) {
            attribute_groups.push_back(tmp);
            return;
        }
        response.cut(0, 1);
        if (response.data_len < 2) {
            return;
        }
        while (!isDelimiterTag(response.data_ptr[0])) {
            Attribute attr;

            if (response.data_len < 1) {
                return;
            }
            attr.tag_id = response.data_ptr[0];
            response.cut(0, 1);

            if (response.data_len < 2) {
                return;
            }
            size_t name_len = response.data_ptr[0] << 8 | response.data_ptr[1];
            response.cut(0, 2);

            if (response.data_len < name_len) {
                return;
            }
            attr.name = std::string(reinterpret_cast<char *>(response.data_ptr), name_len);
            response.cut(0, name_len);

            if (response.data_len < 2) {
                return;
            }
            size_t value_len = response.data_ptr[0] << 8 | response.data_ptr[1];
            response.cut(0, 2);

            if (response.data_len < value_len) {
                return;
            }
            for (int i = 0; i < value_len; i++) {
                attr.value.push_back(response.data_ptr[i]);
            }
            response.cut(0, value_len);
            tmp.attributes.push_back(attr);
        }
        attribute_groups.push_back(tmp);
    }
}

void IppResponse::statusMessageFilter() {
    for (auto &group : attribute_groups) {
        for (auto &attr : group.attributes) {
            if (attr.name == "status-message") {
                printf("attr.value.size()=%zu\n", attr.value.size());
                printf("attr.value=%s\n", std::string(attr.value.begin(), attr.value.end()).c_str());
                // if status-message start with "Bad request version number", delete following data
                if (attr.value.size() >= 25 && std::equal(attr.value.begin(), attr.value.begin() + 25, "Bad request version number")) {
                    // delete data after "Bad request version number"
                    attr.value.erase(attr.value.begin() + 25, attr.value.end());
                } else if (attr.value.size() >= 13 && std::equal(attr.value.begin(), attr.value.begin() + 13, "Bad request-id")) {
                    // delete data after "Bad request version number"
                    attr.value.erase(attr.value.begin() + 13, attr.value.end());
                } else {
                    // find if there is a \" in attr.value
                    auto it = std::find(attr.value.begin(), attr.value.end(), '\"');
                    if (it != attr.value.end()) {
                        // delete data after \"
                        attr.value.erase(it, attr.value.end());
                    }
                }
            }
        }
    }
}

bool IppResponse::isDelimiterTag(uint8_t tag_id) {
    return tag_id >= 0x1 && tag_id <= 0x5;
}

void IppResponse::print() {
    std::cout << to_string() << std::endl;
}

double IppDistance(const std::shared_ptr<IppResponse>& seq1, const std::shared_ptr<IppResponse>& seq2) {
    if (seq1->http_code != seq2->http_code || seq1->status_code != seq2->status_code) {
        return 1;
    }
    
    std::string value1_printer_state, value2_printer_state;
    std::string value1_status_message, value2_status_message;
    bool found_printer_state_1 = false, found_printer_state_2 = false;
    bool found_status_message_1 = false, found_status_message_2 = false;
    
    for (const auto& group : seq1->attribute_groups) {
        for (const auto& attr : group.attributes) {
            if (attr.name == "printer-state") {
                found_printer_state_1 = true;
                value1_printer_state = std::string(attr.value.begin(), attr.value.end());
            } else if (attr.name == "status-message") {
                found_status_message_1 = true;
                value1_status_message = std::string(attr.value.begin(), attr.value.end());
            }
            if (found_printer_state_1 && found_status_message_1) {
                break;
            }
        }
        if (found_printer_state_1 && found_status_message_1) {
            break;
        }
    }

    for (const auto& group : seq2->attribute_groups) {
        for (const auto& attr : group.attributes) {
            if (attr.name == "printer-state") {
                found_printer_state_2 = true;
                value2_printer_state = std::string(attr.value.begin(), attr.value.end());
            } else if (attr.name == "status-message") {
                found_status_message_2 = true;
                value2_status_message = std::string(attr.value.begin(), attr.value.end());
            }
            if (found_printer_state_2 && found_status_message_2) {
                break;
            }
        }
        if (found_printer_state_2 && found_status_message_2) {
            break;
        }
    }

    if ((!found_printer_state_1 &&!found_printer_state_2) || (!found_status_message_1 &&!found_status_message_2)) {
        return 0;
    }

    if ((found_printer_state_1!= found_printer_state_2) || (found_status_message_1!= found_status_message_2)) {
        return 1;
    }

    double similarity_printer_state = stringSimilarity(value1_printer_state, value2_printer_state);
    double similarity_status_message = stringSimilarity(value1_status_message, value2_status_message);
    return 1 - (similarity_printer_state + similarity_status_message) / 2;
}

std::string IppResponse::to_string() {
    std::string result;

    result += "HTTP version: " + std::to_string(http_version) + "\n";
    result += "HTTP status code: " + std::to_string(http_code) + "\n";

    if (version_number != 0) {
        result += "IPP version number: 0x";
        result += to_hex_string((int)version_number, 4);
        result += "\n";
    }

    if (status_code != 0xeeee) {
        result += "IPP status code: 0x";
        result += to_hex_string((int)status_code, 4);
        result += "\n";
    }

    if (request_id != 0) {
        result += "IPP request id: ";
        result += std::to_string(request_id);
        result += "\n";
    }

    for (auto group : attribute_groups) {
        result += "Attribute group:\n";
        result += "  group tag: 0x";
        result += to_hex_string(group.tag_id, 2);
        result += "\n";

        for (auto attr : group.attributes) {
            result += "    attribute tag: 0x";
            result += to_hex_string(attr.tag_id, 2);
            result += "|";
            result += "    attribute name: " + attr.name + "|";
            result += "    attribute value: ";

            for (int i = 0; i < attr.value.size(); i++) {
                result += to_hex_string(attr.value[i], 2) + " ";
            }
            result += "\n";
        }
    }

    return result;
}

bool IppResponse::operator==(const IppResponse &other) const {
    if (http_code != other.http_code) {
        return false;
    }
    if (status_code != other.status_code) {
        return false;
    }
    if (attribute_groups.size() != other.attribute_groups.size()) {
        return false;
    }
    for (int i = 0; i < attribute_groups.size(); i++) {
        if (attribute_groups[i].attributes.size() != other.attribute_groups[i].attributes.size()) {
            return false;
        }
        for (int j = 0; j < attribute_groups[i].attributes.size(); j++) {
            if (attribute_groups[i].attributes[j].tag_id != other.attribute_groups[i].attributes[j].tag_id) {
                return false;
            } else if (attribute_groups[i].attributes[j].name != other.attribute_groups[i].attributes[j].name) {
                return false;
                // * NOTE: compare the value of the attribute while name is `empty` or `status-message` or `job-state-reasons`
            } else if (attribute_groups[i].attributes[j].name == "" || attribute_groups[i].attributes[j].name == "status-message" || attribute_groups[i].attributes[j].name == "job-state-reasons") {
                if (!std::equal(attribute_groups[i].attributes[j].value.begin(), attribute_groups[i].attributes[j].value.end(), other.attribute_groups[i].attributes[j].value.begin(), other.attribute_groups[i].attributes[j].value.end())) {
                    return false;
                }
            }
        }
    }
    return true;
}

bool IppResponse::operator!=(const IppResponse &other) const {
    return !(*this == other);
}

LpdResponse::LpdResponse() {
    data.clear();
}

LpdResponse::LpdResponse(TcpData data) {
    parse(data);
}

LpdResponse::~LpdResponse() {
    data.clear();
}

std::string LpdResponse::to_string() {
    std::stringstream ss;
    for (int i = 0; i < data.size(); i++) {
        ss << "0x" << std::hex << (int)data[i] << " ";
    }
    return ss.str();
}

void LpdResponse::print() {
    std::cout << to_string();
}

bool LpdResponse::operator==(const LpdResponse &other) const {
    return data[0] == other.data[0];
}

bool LpdResponse::operator!=(const LpdResponse &other) const {
    return !(*this == other);
}

void LpdResponse::parse(TcpData response) {
    for (int i = 0; i < response.data_len; i++) {
        data.push_back(response.data_ptr[i]);
    }
    return;
}

double LpdDistance(const std::shared_ptr<LpdResponse>& seq1, const std::shared_ptr<LpdResponse>& seq2) {
    int len1 = seq1->data.size();
    int len2 = seq2->data.size();
    if (len1 == 1) {
        if (len2 != 1) {
            return 1;
        }
        return seq1->data[0] != seq2->data[0];
    } else {
        if (len2 == 1) {
            return 1;
        }
        return stringSimilarity(std::string(seq1->data.begin(), seq1->data.end()), 
                                std::string(seq2->data.begin(), seq2->data.end()));
    }
}
