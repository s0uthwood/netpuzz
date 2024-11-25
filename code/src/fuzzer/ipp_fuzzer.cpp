#include "fuzzer/ipp_fuzzer.hpp"

#include "./utils.hpp"

IPPFuzzer::IPPFuzzer(const std::string &address, int port, unsigned int seed) :
    TCPFuzzer(address, port, seed) {
    return;
}

void IPPFuzzer::setSeedPoolProtocol() {
    seed_pool.protocol = "ipp";
    return;
}

std::vector<std::shared_ptr<Response>> IPPFuzzer::handleResponse(std::vector<TcpData> response) {
    if (response.size() == 0) {
        return std::vector<std::shared_ptr<Response>>();
    }

    std::vector<TcpData> slice_response;
    int pos = 0, last_pos = 0;
    while ((pos = response[0].find("HTTP", last_pos)) != -1) {
        // printf("pos = %d\n", pos);
        if (pos == last_pos) {
            last_pos = pos + 4;
            continue;
        }
        TcpData tmp_response;
        tmp_response.data_len = pos - last_pos + 4;
        tmp_response.data_ptr = reinterpret_cast<u8 *>(malloc(tmp_response.data_len));
        memcpy(tmp_response.data_ptr, response[0].data_ptr + last_pos - 4, tmp_response.data_len);
        slice_response.push_back(tmp_response);
        last_pos = pos + 4;
    }
    if (response[0].data_len - last_pos > 0) {
        TcpData tmp_response;
        tmp_response.data_len = response[0].data_len - last_pos + 4;
        tmp_response.data_ptr = reinterpret_cast<u8 *>(malloc(tmp_response.data_len));
        memcpy(tmp_response.data_ptr, response[0].data_ptr + last_pos - 4, tmp_response.data_len);
        slice_response.push_back(tmp_response);
    }
    std::vector<std::shared_ptr<Response>> responses;
    int response_size = slice_response.size();
    for (size_t i = 0; i < response_size; i++) {
        printf("[Debug] In handleResponse\n");
        // std::cout << slice_response[i].dataToHex() << std::endl;
        // IppResponse *tmp = new IppResponse(slice_response[i]);
        responses.push_back(std::make_shared<IppResponse>(slice_response[i]));
        printf("[Debug] After pushback\n");
        u16 version = (std::dynamic_pointer_cast<IppResponse>(responses.back()))->version_number;
        // if (version != 0 && (version < 0x100 || version > 0x220)) {
        //     crashHandler("Response Format Error!!!" + std::to_string(version));
        // }
        // delete tmp;
    }
    return responses;
}

std::vector<TcpData> IPPFuzzer::sendAndRecv(TestCase &testCase) {
    if (!connectToServer()) {
        std::cout << "Connection closed" << std::endl;
        // result_xml[round % HISTORY_SIZE]["path"] = "Connection closed";
        throw FuzzerException("Connection closed");
        // endFuzzer();
    }
    std::vector<TcpData> response;
    response.push_back(TcpData());
    pthread_t sendThread, recvThread;
    std::atomic<bool> sendThreadEnd(false), recvThreadEnd(false);
    auto *args = new ThreadArgs{this, &testCase, &response, &sendThread, &recvThread, &sendThreadEnd, &recvThreadEnd};
    if (pthread_create(&sendThread, nullptr, sendTestCaseWrapper, args)) {
        perror("Failed to create send thread");
        throw FuzzerException("Failed to create thread");
        // endFuzzer();
    }
    if (pthread_create(&recvThread, nullptr, recvResponseWrapper, args)) {
        perror("Failed to create send thread");
        throw FuzzerException("Failed to create thread");
        // endFuzzer();
    }

    while (!args->sendThreadEnd->load() || !args->recvThreadEnd->load()) {
        // std::cout << "sendThreadEnd: " << args->sendThreadEnd->load() << std::endl;
        // std::cout << "recvThreadEnd: " << args->recvThreadEnd->load() << std::endl;
        // End the recv thread 5 seconds after send thread had ended
        if (args->sendThreadEnd->load()) {
            struct timespec recv_ts;
            if (clock_gettime(CLOCK_REALTIME, &recv_ts) != -1) {
                recv_ts.tv_sec += 5;
                if (pthread_timedjoin_np(recvThread, nullptr, &recv_ts) == ETIMEDOUT) {
                    std::cout << "End Recv thread" << std::endl;
                    pthread_cancel(recvThread);
                    void* thread_result;
                    pthread_join(sendThread, &thread_result);
                    args->recvThreadEnd->store(true);
                }
            }
        }

        // End the send thread if recv thread is stoped
        if (args->recvThreadEnd->load()) {
            std::cout << "End Send thread" << std::endl;
            pthread_cancel(sendThread);
            void* thread_result;
            pthread_join(sendThread, &thread_result);
            args->sendThreadEnd->store(true);
        }
    }

    connect.close();
    delete args;
    return response;
}

bool IPPFuzzer::isInteresting(std::vector<std::shared_ptr<Response>> responses) {
    const double similarity_threshold = 0.1;
    
    std::vector<std::shared_ptr<IppResponse>> ippResponses;
    for (const auto& response : responses) {
        auto ippResponse = std::dynamic_pointer_cast<IppResponse>(response);
        if (!ippResponse) {
            throw std::invalid_argument("All responses must be of type IppResponse");
        }
        ippResponses.push_back(ippResponse);
    }

    for (auto & seed_responses : seed_pool.seedPool) {
        std::vector<std::shared_ptr<IppResponse>> seed_ipp_responses;
        for (const auto& seed_response : seed_responses.responses) {
            auto seedIppResponse = std::dynamic_pointer_cast<IppResponse>(seed_response);
            if (!seedIppResponse) {
                throw std::invalid_argument("All seed responses must be of type IppResponse");
            }
            seed_ipp_responses.push_back(seedIppResponse);
        }

        if (responses.size() == 0) {
            return false;
        }
        double distance = shapeDTW(seed_ipp_responses, ippResponses);
        double similarity = distance / std::max(seed_responses.responses.size(), responses.size());
        if (similarity < similarity_threshold) {
            return false;
        }
    }
    return true;
}

bool IPPFuzzer::isValidRequest(std::vector<std::shared_ptr<Response>> responses) {
    for (const auto & response : responses) {
        if ((std::static_pointer_cast<IppResponse>(response))->http_code == 200)
            return true;
    }
    return false;
}

bool IPPFuzzer::checkSurvivalPath(std::vector<std::shared_ptr<Response>> responses) {
    if (responses.empty()) {
        return false;
    }
    // for (size_t i = 0; i < responses.size(); i++) {
    //     if (((IppResponse *)responses[i])->status_code == 0x507)
    //         return false;
    // }
    return true;
}

// NOTE: Filter all the http headers
TcpData IPPFuzzer::responseFilter(TcpData response) {
    if (response.data_len == 0) {
        TcpData empty_response;
        empty_response.data_ptr = static_cast<uint8_t *>(malloc(1));
        empty_response.data_len = 0;
        empty_response.data_ptr[0] = 0;
        return empty_response;
    }
    // Response is the pure IPP response
    int start_index = 0;
    while ((start_index = response.find("HTTP", start_index)) != -1) {
        int end_index = response.find("\r\n\r\n", start_index);
        if (end_index != -1) {
            response = httpFilter(response, start_index, end_index);
        }
        start_index += 4;
    }
    return response;
}

TcpData IPPFuzzer::httpFilter(TcpData response, int start, int end) {
    // Extract HTTP status line
    TcpData front;
    if (start > 0) {
        front.data_len = start;
        front.data_ptr = reinterpret_cast<u8 *>(malloc(start));
        memcpy(front.data_ptr, response.data_ptr, start);
    }
    TcpData result;
    std::regex header_regex(R"(HTTP/\d\.\d\s\d{3}\s.*\r\n)");
    std::smatch regex_res;
    printf("start: %d\n", start);
    std::string http_response(reinterpret_cast<char *>(response.data_ptr + start), end - start + 4);
    response.cut(0, end + 4);
    if (std::regex_search(http_response, regex_res, header_regex)) {
        result.data_len = regex_res[0].str().size();
        result.data_ptr = static_cast<uint8_t *>(malloc(result.data_len));
        memcpy(result.data_ptr, regex_res[0].str().c_str(), result.data_len);
    }
    return front + result + response;
}
