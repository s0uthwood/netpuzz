#include "./utils.hpp"

#include <algorithm>
#include <cctype>
#include <chrono>
#include <cstdio>
#include <cstring>
#include <iomanip>
#include <iostream>
#include <memory>
#include <sstream>
#include <stdexcept>

std::string getCurrentTime() {
    std::time_t currentTime;
    auto now = std::chrono::system_clock::now();
    currentTime = std::chrono::time_point_cast<std::chrono::seconds>(now).time_since_epoch().count();
    struct tm *localTime = localtime(&currentTime);
    char buffer[80] = {};
    strftime(buffer, sizeof(buffer), "%Y%m%d-%H%M%S", localTime);
    return std::string(buffer);
}

std::string u64ToHexString(u64 input, const std::string &hexcase) {
    std::stringstream hexStream;
    hexStream << std::hex << std::uppercase << input;
    std::string hexString = hexStream.str();
    if (hexcase == "lower") {
        std::transform(hexString.begin(), hexString.end(), hexString.begin(),
                       [](unsigned char c) { return std::tolower(c); });
    } else if (hexcase == "upper") {
        std::transform(hexString.begin(), hexString.end(), hexString.begin(),
                       [](unsigned char c) { return std::toupper(c); });
    } else {
        std::cout << "Error: Invalid hexcase: " << hexcase << std::endl;
    }
    return hexString;
}

std::vector<u8> hexStringToBytes(const std::string &inputString) {
    std::string hexString = inputString;
    std::vector<u8> bytes;
    // Delete all spaces and newlines in hexString
    hexString.erase(std::remove_if(hexString.begin(), hexString.end(), [](char ch) {
                        return ch == ' ' || ch == '\n' || ch == '\r';
                    }),
                    hexString.end());

    bytes.reserve(hexString.length() / 2);

    for (size_t i = 0; i < hexString.length(); i += 2) {
        std::string byteString = hexString.substr(i, 2);
        auto byte = static_cast<u8>(std::stoul(byteString, nullptr, 16));
        bytes.push_back(byte);
    }

    return bytes;
}

std::string stringToHex(const std::string &input) {
    std::stringstream hexStream;
    hexStream << std::hex << std::setfill('0');

    for (char ch : input) {
        hexStream << std::setw(2) << std::setfill('0') << std::hex << static_cast<int>(static_cast<unsigned char>(ch)) << " ";
    }

    std::string hexString = hexStream.str();
    // Remove the last space
    hexString.pop_back();
    return hexString;
}

void u64ToBytes(u64 input, size_t len, bool is_little_endian, std::vector<u8> &bytes) {
    bytes.reserve(len);
    for (size_t i = 0; i < len; ++i) {
        bytes.push_back(static_cast<u8>(input >> (i * 8)));
    }
    if (!is_little_endian) {
        std::reverse(bytes.begin(), bytes.end());
    }
}

std::string to_hex_string(int number, int length) {
    if (length > 16) {
        length = 16;
    } else if (length < 1) {
        length = 1;
    }
    char buffer[32];  // 足以容纳任何 32 位整数的十六进制表示
    snprintf(buffer, sizeof(buffer), "%0*x", length, number);
    return std::string(buffer);
}

u64 parseHexStringAsLittleEndian(const std::string &hex_string, size_t len) {
    std::istringstream converter(hex_string);
    uint64_t value = 0;
    for (size_t i = 0; i < len; ++i) {
        unsigned int byte;
        converter >> std::hex >> byte;
        if (converter.fail()) {
            throw std::runtime_error("Conversion failed.");
        }
        value |= static_cast<uint64_t>(byte) << (i * 8);
        // Ignore the space between bytes
        converter.ignore(1);
    }
    return value;
}

std::vector<std::string> splitString(const std::string &s, char delimiter) {
    std::vector<std::string> tokens;
    std::string token;
    std::istringstream tokenStream(s);

    while (std::getline(tokenStream, token, delimiter)) {
        tokens.push_back(token);
    }

    return tokens;
}

std::string executeCommand(const std::string &command) {
    std::string result;
    FILE *pipe = popen(command.c_str(), "r");
    if (!pipe) {
        printf("popen() failed!\n");
        throw std::runtime_error("popen() failed!");
    }
    char buf[1025] = {0};
    while (fgets(buf, 1024, pipe) != nullptr) {
        result.append(buf);
    }
    int status = pclose(pipe);
    int exit_status = WEXITSTATUS(status);
    if (exit_status != 0) {
        printf("Command failed with exit status %d\n", exit_status);
        throw std::runtime_error("Command failed");
    }
    return result;
}

std::string toLower(const std::string &str) {
    std::string result = str;
    std::transform(result.begin(), result.end(), result.begin(), ::tolower);
    return result;
}
