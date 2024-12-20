#ifndef INCLUDE_UTILS_HPP_
#define INCLUDE_UTILS_HPP_

#include <string>
#include <vector>
#include <limits>
#include <functional>

#include "./defines.hpp"
#include "fuzzer/response.hpp"

std::string getCurrentTime();

std::string u64ToHexString(u64 input, const std::string &hexcase);
std::vector<u8> hexStringToBytes(const std::string &hexString);
std::string stringToHex(const std::string &input);
void u64ToBytes(u64 input, size_t len, bool is_little_endian, std::vector<u8> &bytes);
std::string to_hex_string(int number, int length);
u64 parseHexStringAsLittleEndian(const std::string &hexString, size_t len);
std::vector<std::string> splitString(const std::string &inputString, char delimiter);
std::string toLower(const std::string &str);

std::string executeCommand(const std::string &command);

double stringSimilarity(const std::string& s1, const std::string& s2);

template <typename T>
using DistanceFunc = double(*)(const T&, const T&);

template <typename T>
double shapeDTW(const std::vector<T>& seq1, const std::vector<T>& seq2, DistanceFunc<T> distanceMetric){
    size_t len1 = seq1.size();
    size_t len2 = seq2.size();
    std::vector<std::vector<double>> dtw(len1 + 1, std::vector<double>(len2 + 1, std::numeric_limits<double>::max()));
    dtw[0][0] = 0.0;

    for (size_t i = 1; i <= len1; ++i) {
        for (size_t j = 1; j <= len2; ++j) {
            double cost = distanceMetric(seq1[i - 1], seq2[j - 1]);
            dtw[i][j] = cost + std::min(std::min(dtw[i - 1][j], dtw[i][j - 1]), dtw[i - 1][j - 1]);
        }
    }
    return dtw[len1][len2];
}

#endif  // INCLUDE_UTILS_HPP_
