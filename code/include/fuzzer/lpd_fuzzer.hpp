#ifndef INCLUDE_FUZZER_LPD_FUZZER_HPP_
#define INCLUDE_FUZZER_LPD_FUZZER_HPP_

#include <string>
#include <vector>

#include "fuzzer/tcp_fuzzer.hpp"

class LPDFuzzer : public TCPFuzzer {
 public:
    LPDFuzzer(const std::string &address, int port, unsigned int seed);

    void setSeedPoolProtocol() override;
    std::vector<TcpData> sendAndRecv(TestCase &testCase) override;
    std::vector<std::shared_ptr<Response>> handleResponse(std::vector<TcpData> response) override;
    bool isInteresting(std::vector<std::shared_ptr<Response>> responses) override;
    bool checkSurvivalPath(std::vector<std::shared_ptr<Response>> responses) override;
};

#endif  // INCLUDE_FUZZER_LPD_FUZZER_HPP_
