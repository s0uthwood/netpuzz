#include "fuzzer/lpd_fuzzer.hpp"

#include <memory>

#include "./utils.hpp"

LPDFuzzer::LPDFuzzer(const std::string &address, int port, unsigned int seed) :
    TCPFuzzer(address, port, seed) {
    }

void LPDFuzzer::setSeedPoolProtocol() {
    seed_pool.protocol = "lpd";
}

std::vector<TcpData> LPDFuzzer::sendAndRecv(TestCase &testCase) {
    if (!connectToServer()) {
        std::cout << "Connection closed" << std::endl;
        throw FuzzerException("Connection closed");
    }
    std::vector<TcpData> response;
    TcpData tmp;
    try {
        for (auto &data : testCase.getDataList()) {
            int flags = 0;
            // printf("Send data: %s\n", data.dataToHex().c_str());
            // printf("Sending\n");
            connect.send(data.tcp_data.data_ptr, data.tcp_data.data_len, flags);
            int valread = connect.receive(&tmp);
            if (valread == 0) {
                std::cout << "Closed" << std::endl;
                break;
            } else if (valread < 0) {
                std::cout << "Receive data failed" << std::endl;
                tmp.data_len = 1;
                if (tmp.data_ptr) {
                    free(tmp.data_ptr);
                }
                tmp.data_ptr = static_cast<u8 *>(malloc(1));
                tmp.data_ptr[0] = 0x45;
            } 
            response.push_back(tmp);
        }
        // printf("Send data finished\n");
    } catch (TCPConnectException &e) {
        std::cout << "******** Seed Testcase error ********" << std::endl;
        printf("Crash in sendTestCase: %s\n", e.what());
    }
    connect.close();
    return response;
}

std::vector<std::shared_ptr<Response>> LPDFuzzer::handleResponse(std::vector<TcpData> response) {
    std::vector<std::shared_ptr<Response>> responses;
    for (auto & i : response) {
        // LpdResponse *tmp = new LpdResponse(response[i]);
        responses.push_back(std::make_shared<LpdResponse>(i));
    }
    return responses;
}

bool LPDFuzzer::isInteresting(std::vector<std::shared_ptr<Response>> responses) {
    const double similarity_threshold = 0.1;

    std::vector<std::shared_ptr<LpdResponse>> lpd_responses;
    for (const auto& response : responses) {
        auto lpd_response = std::dynamic_pointer_cast<LpdResponse>(response);
        if (!lpd_response) {
            throw std::invalid_argument("All responses must be of type IppResponse");
        }
        lpd_responses.push_back(lpd_response);
    }

    for (auto & seed_responses : seed_pool.seedPool) {
        std::vector<std::shared_ptr<LpdResponse>> seed_lpd_responses;
        for (const auto& seed_response : seed_responses.responses) {
            auto seed_lpd_response = std::dynamic_pointer_cast<LpdResponse>(seed_response);

            if (!seed_lpd_response) {
                throw std::invalid_argument("All seed responses must be of type IppResponse");
            }
            seed_lpd_responses.push_back(seed_lpd_response);
        }

        if (responses.size() == 0) {
            return false;
        }
        double distance = shapeDTW(seed_lpd_responses, lpd_responses);
        double similarity = distance / std::max(seed_responses.responses.size(), responses.size());
        if (similarity < similarity_threshold) {
            return false;
        }
    }
    return true;
}

bool LPDFuzzer::checkSurvivalPath(std::vector<std::shared_ptr<Response>> responses) {
    if (responses.empty()) {
        return false;
    }
    for (const auto & response : responses) {
        if (!(std::static_pointer_cast<LpdResponse>(response))->data.empty() && (std::static_pointer_cast<LpdResponse>(response))->data[0] != 0x45)
            return true;
    }
    return false;
}
