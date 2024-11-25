#include "fuzzer/tcp_fuzzer.hpp"

#include <netinet/in.h>
#include <pthread.h>

#include <csignal>
#include <chrono>
#include <cstdlib>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>

#include "./utils.hpp"
#include "fuzzer/test_case.hpp"
#include "./xml_extension.hpp"

TCPFuzzer::TCPFuzzer(const std::string &address, int port, unsigned int seed) :
    mutator(seed) {
    connect.setAddress(address, port);
    round = 0;
    result_xml = pugi::xml_document();
}

void TCPFuzzer::setConnectAddress(const std::string &address, int port) {
    connect.setAddress(address, port);
}

bool TCPFuzzer::connectToServer() {
    try {
        connect.connect();
    } catch (TCPConnectException &e) {
        std::cout << e.what() << std::endl;
        return false;
    }
    return true;
}

void TCPFuzzer::closeConnection() {
    connect.~TCPConnect();
}

void TCPFuzzer::setOriginTestCase(const TestCase &testCase) {
    this->origin_testcase = TestCase();
    for (auto &data : testCase.getDataList()) {
        PacketData newData = PacketData(data);
        this->origin_testcase.data_list.push_back(newData);
    }
}

TestCase TCPFuzzer::getOriginTestCase() {
    return this->origin_testcase;
}

TestCase TCPFuzzer::getTestcaseFromInputXml() {
    TestCase input_testcase = TestCase();
    input_testcase.generateFromInputXml();
    return input_testcase;
}

void TCPFuzzer::setFuzzedTestCase() {
    fuzzed_testcase = getTestcaseFromInputXml();
}

bool TCPFuzzer::mutateInputXml() {
    std::string input_file = ::log_dir + INPUT_FILE_NAME;
    pugi::xml_document input_doc;
    pugi::xml_parse_result result = input_doc.load_file(input_file.c_str());
    if (!result) {
        std::cout << "Load input.xml failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    pugi::xml_node root = input_doc.child("Sequence");
    pugi::xml_node selected_leaf;
    size_t mutate_count;
    pugi::xml_node selected_node;
    std::string selected_node_name;

    // pick a mutate stage <= mutate_stage
    // Which makes STAGE_3 can also cover STAGE_1 and STAGE_2
    auto mutate_strategy = (MutateStage)(rand() % ((int)mutate_stage + 1));
    std::cout << "Mutate stage: " << static_cast<int>(mutate_strategy) << std::endl;
    switch (mutate_strategy) {
    case MutateStage::STAGE_1:
        std::cout << "Mutate stage 1" << std::endl;
        mutate_count = rand() % MAX_MUTATION_COUNT + 1;
        std::cout << "Mutate count: " << mutate_count << std::endl;
        for (int i = 0; i < mutate_count; i++) {
            std::cout << "Mutate " << i << std::endl;
            selected_leaf = mutator.selectRandLeaf(root);
            std::cout << selected_leaf.attribute("value").value() << std::endl;
            bool mutate_result = mutator.mutateRandValue(selected_leaf);
            std::cout << "Mutate " << i << " finished" << std::endl;
            std::cout << selected_leaf.attribute("value").value() << std::endl;
        }
        break;
    case MutateStage::STAGE_2:
        std::cout << "Mutate stage 2" << std::endl;
        mutate_count = rand() % MAX_MUTATION_COUNT + 1;
        std::cout << "Mutate count: " << mutate_count << std::endl;
        for (int i = 0; i < mutate_count; i++) {
            std::cout << "Mutate " << i << std::endl;
            
            selected_node = mutator.selectRandNode(root);
            selected_node_name = selected_node.name();

            if (selected_node_name == "Sequence") {
                selected_node = mutator.selectRandChild(selected_node);
                mutator.mutatePacketDelay(selected_node);
            } else {
                mutator.mutateBlockChild(selected_node);
            }

            std::cout << "Mutate " << i << " finished" << std::endl;
        }
        break;
    case MutateStage::STAGE_3:
        std::cout << "Mutate stage 2" << std::endl;
        mutate_count = rand() % MAX_MUTATION_COUNT + 1;
        std::cout << "Mutate count: " << mutate_count << std::endl;
        for (int i = 0; i < mutate_count; i++) {
            std::cout << "Mutate " << i << std::endl;

            selected_node = mutator.selectRandNode(root);
            mutator.mutateBlockChild(selected_node);

            std::cout << "Mutate " << i << " finished" << std::endl;
        }
        break;
    default:
        break;
    }
    // check result
    root = input_doc.child("Sequence");
    if (root.empty()) {
        return false;
    }
    pugi::xml_node check_child = mutator.selectRandChild(root);
    if (check_child.empty()) 
        return false;
    if (check_child == root) {
        return false;
    }
    // save input.xml
    input_doc.save_file(input_file.c_str());
    return true;
}

// NOTE: send data function for thread
void TCPFuzzer::sendTestCase(TestCase &testCase) {
    try {
        for (auto &data : testCase.getDataList()) {
            int flags = 0;
            // printf("Send data: %s\n", data.dataToHex().c_str());
            // printf("Sending\n");
            connect.send(data.tcp_data.data_ptr, data.tcp_data.data_len, flags);
            if (data.delay_time > MAX_DELAY) {
                break;
            } else if (data.delay_time > MIN_DELAY) {
                usleep(data.delay_time * 1000);
            }
        }
        // printf("Send data finished\n");
    } catch (TCPConnectException &e) {
        std::cout << "******** Seed Testcase error ********" << std::endl;
        printf("Crash in sendTestCase: %s\n", e.what());
    }
}

// NOTE: recv data function for thread
void TCPFuzzer::recvResponse(std::vector<TcpData> &response) {
    try {
        int recv_flag = 1;
        while (recv_flag != 0) {
            TcpData res;
            recv_flag = connect.receive(&res);
            std::cout << res.dataToHex() << std::endl;
            // std::cout << "Recv response" << std::endl;
            TcpData filtered_response = this->responseFilter(res);
            if (response.empty()) {
                response.push_back(filtered_response);
            } else {
                response[0] += filtered_response;
            }
        }
    } catch (TCPConnectException &e) {
        std::cout << "******** Recv Response error ********" << std::endl;
        printf("Crash in recvResponse: %s\n", e.what());
        return;
    } catch (TCPTimeoutException &e) {
        std::cout << "******** Recv Response error ********" << std::endl;
        printf("Timeout in recvResponse: %s\n", e.what());
        return;
    } catch (std::exception &e) {
        std::cout << "******** Recv Response error ********" << std::endl;
        printf("Exception in recvResponse: %s\n", e.what());
        return;
    }
    }

bool TCPFuzzer::setDeviceController(const std::string& filename) {
    return device_controller.getSwCmdFromXml(filename) && device_controller.getMonitorCmdFromXml(filename);
}

std::vector<TcpData> TCPFuzzer::sendAndRecv(TestCase &testCase) {
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
    if (pthread_create(&sendThread, NULL, sendTestCaseWrapper, args)) {
        perror("Failed to create send thread");
        throw FuzzerException("Failed to create thread");
        // endFuzzer();
    }
    if (pthread_create(&recvThread, NULL, recvResponseWrapper, args)) {
        perror("Failed to create send thread");
        throw FuzzerException("Failed to create thread");
        // endFuzzer();
    }

    while (!args->sendThreadEnd->load() || !args->recvThreadEnd->load()) {
        // std::cout << "sendThreadEnd: " << args->sendThreadEnd->load() << std::endl;
        // std::cout << "recvThreadEnd: " << args->recvThreadEnd->load() << std::endl;
        // End recv thread 5 seconds after send thread ended
        if (args->sendThreadEnd->load()) {
            struct timespec recv_ts{};
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

        // End send thread if recv thread is end
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

std::vector<TcpData> TCPFuzzer::testSurvival() {
    printf("-------------------- Survival test --------------------\n");
    std::vector<TcpData> cur_resp;
    try {
        cur_resp = sendAndRecv(this->origin_testcase);
        closeConnection();
    } catch (TCPConnectException &e) {
        std::cout << "******** Survival test error ********" << std::endl;
        printf("%s\n", e.what());
        // endFuzzer();
        crashHandler("Connection closed: " + std::string(e.what()));
    } catch (TCPTimeoutException &e) {
        std::cout << "******** Survival test error ********" << std::endl;
        printf("%s\n", e.what());
        crashHandler("Timeout error: " + std::string(e.what()));
        // endFuzzer();
    } catch (FuzzerException &e) {
        std::cout << "******** Survival test error ********" << std::endl;
        printf("%s\n", e.what());
        crashHandler("Fuzzer error: " + std::string(e.what()));
        // endFuzzer();
    }
    return cur_resp;
}

bool TCPFuzzer::checkSurvivalPath(std::vector<std::shared_ptr<Response>> responses) {
    return true;
}

void TCPFuzzer::debug(std::vector<std::shared_ptr<Response>> responses) {
    for (size_t i = 0; i < responses.size(); i++) {
        if (responses[i] == nullptr) {
            std::cout << "Response " << i << " is nullptr" << std::endl;
            continue;
        } else {
            responses[i]->print();
        }
    }
    std::cout << std::endl
              << std::endl;
}

std::vector<std::shared_ptr<Response>> TCPFuzzer::handleResponse(std::vector<TcpData> response) {
    return std::vector<std::shared_ptr<Response> >();
}

bool TCPFuzzer::isValidRequest(std::vector<std::shared_ptr<Response>> responses) {
    return true;
}

bool TCPFuzzer::isInteresting(std::vector<std::shared_ptr<Response>> responses) {
    return true;
}

TcpData TCPFuzzer::responseFilter(TcpData response) {
    return response;
}

void TCPFuzzer::setSeedPoolProtocol() {
    seed_pool.protocol = "";
}

void TCPFuzzer::init() {
    // NOTE: restart SUT before starting test
    device_controller.restartDevice();
    need_restart = false;
    last_restart_round = 0;
    all_crash_count = 0;

    setSeedPoolProtocol();
    // NOTE: set the input.xml as origin testcase
    setOriginTestCase(TestCase(::log_dir + INPUT_FILE_NAME));
    try {
        origin_response = sendAndRecv(origin_testcase);
    } catch (TCPConnectException &e) {
        printf("******** Survival test error ********\n");
        printf("Crash in init: %s\n", e.what());
        endFuzzer();
    } catch (TCPTimeoutException &e) {
        printf("******** Survival test error ********\n");
        printf("Crash in init: %s\n", e.what());
        endFuzzer();
    } catch (FuzzerException &e) {
        printf("******** Survival test error ********\n");
        printf("Crash in init: %s\n", e.what());
        endFuzzer();
    }

    std::vector<std::shared_ptr<Response>> responses = handleResponse(origin_response);
    debug(responses);
    seed_pool.addNewSeed(responses);

    if (connect.getPort() == 631) {
        system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
    }

    // NOTE: set the initial mutate stage
    mutate_stage = MutateStage::STAGE_1;
    last_seed_round = 0;

    // NOTE: set ref xml file
    mutator.readReference(::log_dir + REF_FILE_NAME);

    // NOTE: set start time
    start_timestamp = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
    round = 1;

    std::ofstream logfd(::log_dir + "fuzz_log.txt");
    if (!logfd.is_open()) {
        std::cerr << "Can't open log file" << std::endl;
    } else {
        logfd << std::left << std::setw(20) << "Time" << std::left << std::setw(20) << "Round" << std::left << std::setw(20) << "Mutate stage" << std::left << std::setw(20) << "Coverage" << std::left << std::setw(20) << "Crash found" << std::endl;
        logfd.close();
    }

    // NOTE: init rand
    srand(time(nullptr));

    // NOTE: init result xml
    log_node = result_xml.append_child("Log");
    pugi::xml_node cur_log = log_node.append_child("Connection");
    cur_log.append_attribute("round") = 0;
    pugi::xml_node request_node = cur_log.append_child("Request");
    for (auto origin_data : origin_testcase.getDataList()) {
        pugi::xml_node data_node = request_node.append_child("Data");
        // std::cout << origin_data.dataToHex().c_str() << std::endl;
        data_node.text().set(origin_data.dataToHex().c_str());
        data_node.append_attribute("delay") = origin_data.delay_time;
    }
    pugi::xml_node response_node = cur_log.append_child("Response");
    for (size_t i = 0; i < origin_response.size(); i++) {
        response_node.append_child("Data").text().set(origin_response[i].dataToHex().c_str());
    }
    std::cout << "++++++++++++ FINISH INIT ++++++++++++" << std::endl;
}

void TCPFuzzer::run() {
    while (true) {
        current_power = MUTATION_TIMES;
        while (current_power--) {
            pugi::xml_node cur_log = log_node.append_child("Connection");
            // NOTE: mutate the input.xml everytime
            bool mutate_result = mutateInputXml();
            std::cout << "Finish mutating input.xml" << std::endl;
            if (mutate_result == false) {
                current_power = 0;
                continue;
            }

            setFuzzedTestCase();

            usleep(SLEEP_UTIME);
            std::cout << std::endl
                      << "========================================"
                      << std::endl;
            printf("                ROUND %ld\n", round);
            std::cout << "========================================"
                      << std::endl
                      << std::endl;
            cur_log.append_attribute("round") = round;
            // printf("restart_time: %d\n", restart_time);

            // NOTE: restart device if needed or restart round is set
            bool is_restart = false;
            if (need_restart) {
                is_restart = device_controller.restartDevice();
                cur_log.append_attribute("restart") = is_restart;
                if (is_restart == false) {
                    std::cout << "******** Restart failed ********" << std::endl;
                    endFuzzer();
                }
            } else if (device_controller.restart_round > 0) {
                if (round - last_restart_round >= device_controller.restart_round) {
                    is_restart = device_controller.restartDevice();
                    cur_log.append_attribute("restart") = is_restart;
                } else {
                    cur_log.append_attribute("restart") = false;
                }
            } else {
                cur_log.append_attribute("restart") = false;
            }

            if (is_restart) {
                need_restart = false;
                last_restart_round = round;
            }

            std::string timestamp = getCurrentTime();
            cur_log.append_attribute("timestamp") = timestamp.c_str();

            // NOTE: add test case to log.xml
            pugi::xml_node request_node = cur_log.append_child("Request");
            for (auto fuzzed_data : fuzzed_testcase.getDataList()) {
                pugi::xml_node data_node = request_node.append_child("Data");
                // std::cout << fuzzed_data.dataToHex().c_str() << std::endl;
                data_node.text().set(fuzzed_data.dataToHex().c_str());
                data_node.append_attribute("delay") = fuzzed_data.delay_time;
            }

            // NOTE: fuzzer
            std::vector<TcpData> cur_resp;
            try {
                cur_resp = sendAndRecv(fuzzed_testcase);
                closeConnection();
            } catch (TCPConnectException &e) {
                std::cout << "******** Fuzzer error ********" << std::endl;
                printf("%s\n", e.what());
                // crashHandler("Connection closed: " + std::string(e.what()));
            } catch (TCPTimeoutException &e) {
                std::cout << "******** Fuzzer error ********" << std::endl;
                printf("%s\n", e.what());
                // crashHandler("Timeout error: " + std::string(e.what()));
            } catch (FuzzerException &e) {
                std::cout << "******** Fuzzer error ********" << std::endl;
                printf("%s\n", e.what());
                // crashHandler("Fuzzer error: " + std::string(e.what()));
            }

            // NOTE: add response to log.xml
            pugi::xml_node response_node = cur_log.append_child("Response");
            std::cout << "Start parse" << std::endl;
            for (size_t i = 0; i < cur_resp.size(); i++) {
                std::cout << i << std::endl;
                std::cout << cur_resp[i].dataToHex() << std::endl;
                response_node.append_child("Data").text().set(cur_resp[i].dataToHex().c_str());
            }

            // NOTE: handle response and check if interesting
            std::vector<std::shared_ptr<Response>> responses = handleResponse(cur_resp);
            debug(responses);
            // NOTE: check if request is valid
            if (!isValidRequest(responses)) {
                std::cout << "[" + getCurrentTime() + "] "
                          << "Invalid request" << std::endl;
                // end current seed, start next seed
                current_power = 0;
            } else 
            if (isInteresting(responses)) {
                seed_pool.addNewSeed(responses);
                last_seed_round = round;
            }

            // NOTE: collect coverage
            int coverage = seed_pool.getCoverage();
            cur_log.append_attribute("coverage") = coverage;
            closeConnection();

            if (connect.getPort() == 631) {
                system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
            }
            // NOTE: end fuzzer

            std::cout << "Coverage: " << coverage << std::endl;
            usleep(SLEEP_UTIME);

            // Resend initial packet
            int survival_round = 3;
            while (survival_round--) {
                std::vector<TcpData> test_resp = testSurvival();
                pugi::xml_node survival_node = cur_log.append_child("Survival");
                for (auto & resp : test_resp) {
                    survival_node.append_child("Data").text().set(resp.dataToHex().c_str());
                }

                std::vector<std::shared_ptr<Response>> survival_responses = handleResponse(test_resp);
                debug(survival_responses);
                if (connect.getPort() == 631) {
                    system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
                }

                if (!checkSurvivalPath(survival_responses)) {
                    std::cout << "******** Survival test failed ********" << std::endl;
                    if (cur_log.attribute("survival_test")) {
                        cur_log.attribute("survival_test").set_value(false);
                    } else {
                        cur_log.append_attribute("survival_test").set_value(false);
                    }
                } else {
                    std::cout << "-------- Survival test passed --------" << std::endl;
                    if (cur_log.attribute("survival_test")) {
                        cur_log.attribute("survival_test").set_value(true);
                    } else {
                        cur_log.append_attribute("survival_test").set_value(true);
                    }
                    break;
                }

            }

            // NOTE: Survival test failed then save the crash log
            if (cur_log.attribute("survival_test").as_bool() == false) {
                crashHandler("Survival test failed");
            }

            // Monitor test
            bool monitor_result = snmp_monitor();

            if (!monitor_result) {
                std::cout << "******** Monitor test failed ********" << std::endl;
                cur_log.append_attribute("monitor_test").set_value(false);
                crashHandler("Monitor test failed");
            } else {
                std::cout << "-------- Monitor test passed --------" << std::endl;
                cur_log.append_attribute("monitor_test").set_value(true);
            }
            std::cout << std::flush;
            saveLogHandler();
            round++;
        }

        seed_pool.nextSeed();
        if (mutate_stage == MutateStage::STAGE_1) {
            if (round - last_seed_round >= STAGE_UPGRADE_ROUND) {
                mutate_stage = MutateStage::STAGE_2;
            } 
        } else if (mutate_stage == MutateStage::STAGE_2) {
            if (round - last_seed_round >= STAGE_UPGRADE_ROUND * 2) {
                mutate_stage = MutateStage::STAGE_3;
            }
        }
    }
}

TestCase TCPFuzzer::get_request_from_connection(const pugi::xml_node& connection_node) {
    TestCase tmp;
    for (const auto &data_node : connection_node.child("Request").children("Data")) {
        TcpData tcp_data;
        std::string hex_data = data_node.text().as_string();
        std::vector<u8> data_vec = hexStringToBytes(hex_data);
        tcp_data.data_ptr = reinterpret_cast<uint8_t *>(malloc(data_vec.size()));
        tcp_data.data_len = data_vec.size();
        memcpy(tcp_data.data_ptr, data_vec.data(), data_vec.size());
        tmp.data_list.push_back((PacketData){tcp_data, data_node.attribute("delay").as_uint()});
    }
    return tmp;
}

void TCPFuzzer::restart_device() {
    bool result = false;
    while (!result) {
        result = device_controller.restartDevice();
        if (!result) {
            std::cout << "******** Restart failed ********" << std::endl;
            std::cout << "waitting for user to restart" << std::endl;
            std::cout << "Press any key to continue" << std::endl;
            getchar();
        }
        
        int survival_round = 3;
        while (survival_round--) {
            std::vector<TcpData> test_resp;
            try {
                test_resp = sendAndRecv(origin_testcase);
                closeConnection();
            } catch (TCPConnectException &e) {
                std::cout << "******** Survival test error ********" << std::endl;
                printf("%s\n", e.what());
                result = false;
            } catch (TCPTimeoutException &e) {
                std::cout << "******** Survival test error ********" << std::endl;
                printf("%s\n", e.what());
                result = false;
            } catch (FuzzerException &e) {
                std::cout << "******** Survival test error ********" << std::endl;
                printf("%s\n", e.what());
                result = false;
            }
            for (size_t i = 0; i < test_resp.size(); i++) {
                std::cout << "Response " << i << ": " << test_resp[i].dataToHex() << std::endl;
            }
            if (connect.getPort() == 631) {
                system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
            }
            std::vector<std::shared_ptr<Response>> survival_responses = handleResponse(test_resp);
            debug(survival_responses);
            if (!checkSurvivalPath(survival_responses)) {
                std::cout << "******** Survival test failed ********" << std::endl;
                result = false;
            } else {
                std::cout << "-------- Survival test passed --------" << std::endl;
                result = true;
                break;
            }
            sleep(10);
        }
    }
}

bool TCPFuzzer::snmp_monitor() {
    int monitor_result = 0;
    for (int i = 0; (i < 5) && monitor_result == 0; i++) {
        monitor_result = device_controller.monitorDevice();
        sleep(1);
    }
    return monitor_result == 1;
}

void TCPFuzzer::run_poc(const std::string& filename, int start_round, int target_round) {
    // get result_xml from log_file
    pugi::xml_parse_result result = result_xml.load_file(filename.c_str());
    if (!result) {
        std::cout << "Load log.xml failed" << std::endl;
        exit(EXIT_FAILURE);
    }

    // set origin_testcase as round 0 in log.xml
    pugi::xml_node origin_connection = result_xml.child("Log").child("Connection");
    TestCase tmp = get_request_from_connection(origin_connection);
    setOriginTestCase(tmp);

    // read from result_xml, save all Connection in Log to vector
    std::vector<pugi::xml_node> connections;
    for (pugi::xml_node connection : result_xml.child("Log").children("Connection")) {
        if (connection.attribute("round").as_int() < start_round) {
            continue;
        }
        // start from last restart
        if (connection.attribute("restart").as_bool()) {
            connections.clear();
        }
        connections.push_back(connection);
        if (target_round >= 0 && connection.attribute("round").as_int() >= target_round) {
            break;
        }
    }

    restart_device();
    origin_testcase.debugPrint();
    origin_response = testSurvival();

    // get start time
    auto start_time = std::chrono::high_resolution_clock::now();

    size_t connections_size = connections.size();
    std::cout << "Origin size: " << connections_size << std::endl;
    int test_end = -1;
    // STAGE 0: run from start, find where to crash
    std::cout << "=========================" << std::endl;
    std::cout << "|        STAGE 0        |" << std::endl;
    std::cout << "=========================" << std::endl;
    for (size_t i = 0; i < connections_size; i++) {
        printf("Current index: %d\n", connections[i].attribute("round").as_int());
        pugi::xml_node connection = connections[i];
        TestCase testcase = TestCase();
        testcase = get_request_from_connection(connection);
        bool valid = true;
        std::vector<TcpData> cur_resp;
        try {
            cur_resp = sendAndRecv(testcase);
            closeConnection();
            std::vector<std::shared_ptr<Response>> cur_response = handleResponse(cur_resp);
            debug(cur_response);
        } catch (TCPConnectException &e) {
            std::cout << "******** Testcase connection error ********" << std::endl;
            printf("%s\n", e.what());
            valid = false;
        } catch (TCPTimeoutException &e) {
            std::cout << "******** Testcase timeout error ********" << std::endl;
            printf("%s\n", e.what());
            valid = false;
        } catch (FuzzerException &e) {
            std::cout << "******** Testcase error ********" << std::endl;
            printf("%s\n", e.what());
            valid = false;
        }
        if (connect.getPort() == 631) {
            system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
        }
        printf("-------------------- Survival test --------------------\n");
        int survival_round = 3;
        while (survival_round--) {
            std::vector<TcpData> test_resp;
            try {
                test_resp = sendAndRecv(origin_testcase);
                closeConnection();
            } catch (TCPConnectException &e) {
                std::cout << "******** Survival test error ********" << std::endl;
                printf("%s\n", e.what());
                valid = false;
            } catch (TCPTimeoutException &e) {
                std::cout << "******** Survival test error ********" << std::endl;
                printf("%s\n", e.what());
                valid = false;
            } catch (FuzzerException &e) {
                std::cout << "******** Survival test error ********" << std::endl;
                printf("%s\n", e.what());
                valid = false;
            }
            for (size_t j = 0; j < test_resp.size(); j++) {
                std::cout << "Response " << j << ": " << test_resp[j].dataToHex() << std::endl;
            }
            if (connect.getPort() == 631) {
                system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
            }
            std::vector<std::shared_ptr<Response>> survival_responses = handleResponse(test_resp);
            debug(survival_responses);
            if (!checkSurvivalPath(survival_responses)) {
                std::cout << "******** Survival test failed ********" << std::endl;
                std::cout << "Error survival path found at index: " << i << std::endl;
                valid = false;
            } else {
                std::cout << "-------- Survival test passed --------" << std::endl;
                valid = true;
                break;
            }
        }

        valid &= snmp_monitor();
        if (!valid) {
            test_end = i;
            break;
        }
    }

    // calculate stage 0 time
    auto time1 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> stage0_time = time1 - start_time;
    std::cout << "Stage 0 time: " << stage0_time.count() << "s" << std::endl;

    printf("Test end: %d\n", test_end);
    if (test_end == -1) {
        std::cout << "No crash found" << std::endl;
        return;
    }
    restart_device();

    // delete all connections in vector from test_end to end
    for (size_t i = test_end + 1; i < connections_size; i++) {
        connections.pop_back();
    }
    // add each survival test data after a element in connections
    for (int i = connections.size() - 1; i > 0; --i) {
        connections.insert(connections.begin() + i, origin_connection);
    }
    connections_size = connections.size();

    // STAGE 1: find minimal start by bisection
    std::cout << "=========================" << std::endl;
    std::cout << "|        STAGE 1        |" << std::endl;
    std::cout << "=========================" << std::endl;
    int cur_grind = connections_size / 2;
    while (cur_grind > 0) {
        int cur_start = 0;
        if (cur_grind > connections_size / 2) {
            cur_grind = connections_size;
        }
        while (cur_start + cur_grind < connections_size) {
            bool valid = true;
            for (size_t i = 0; i < connections_size && valid; i++) {
                if (i >= cur_start && i < cur_start + cur_grind) {
                    continue;
                }
                pugi::xml_node connection = connections[i];
                TestCase testcase = get_request_from_connection(connection);
                printf("Current index: %d\n", connections[i].attribute("round").as_int());
                try {
                    sendAndRecv(testcase);
                } catch (TCPConnectException &e) {
                    std::cout << "******** Survival test error ********" << std::endl;
                    printf("%s\n", e.what());
                    valid = false;
                } catch (TCPTimeoutException &e) {
                    std::cout << "******** Survival test error ********" << std::endl;
                    printf("%s\n", e.what());
                    valid = false;
                } catch (FuzzerException &e) {
                    std::cout << "******** Survival test error ********" << std::endl;
                    printf("%s\n", e.what());
                    valid = false;
                }

                if (connect.getPort() == 631) {
                    system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
                }
            }
            // check if target still alive
            printf("-------------------- Survival test --------------------\n");
            int survival_round = 3;
            while (survival_round--) {
                std::vector<TcpData> test_resp;
                try {
                    test_resp = sendAndRecv(origin_testcase);
                    closeConnection();
                } catch (TCPConnectException &e) {
                    std::cout << "******** Survival test error ********" << std::endl;
                    printf("%s\n", e.what());
                    valid = false;
                } catch (TCPTimeoutException &e) {
                    std::cout << "******** Survival test error ********" << std::endl;
                    printf("%s\n", e.what());
                    valid = false;
                } catch (FuzzerException &e) {
                    std::cout << "******** Survival test error ********" << std::endl;
                    printf("%s\n", e.what());
                    valid = false;
                }
                for (size_t i = 0; i < test_resp.size(); i++) {
                    std::cout << "Response " << i << ": " << test_resp[i].dataToHex() << std::endl;
                }
                if (connect.getPort() == 631) {
                    system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
                }
                std::vector<std::shared_ptr<Response>> survival_responses = handleResponse(test_resp);
                debug(survival_responses);
                if (!checkSurvivalPath(survival_responses)) {
                    std::cout << "******** Survival test failed ********" << std::endl;
                    valid = false;
                } else {
                    std::cout << "-------- Survival test passed --------" << std::endl;
                    valid = true;
                    break;
                }
            }

            valid &= snmp_monitor();
            if (valid) {
                cur_start += cur_grind;
            } else {
                // delete all connections in vector from cur_start to cur_start + cur_grind
                for (size_t i = cur_start; i < cur_start + cur_grind; i++) {
                    connections.erase(connections.begin() + cur_start);
                }
                connections_size = connections.size();
                cur_grind = connections_size;
            }
            restart_device();
        }
        cur_grind /= 2;
    }

    // calculate stage 1 time
    auto time2 = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> stage1_time = time2 - time1;
    std::cout << "Stage 1 time: " << stage1_time.count() << "s" << std::endl;

    // stage 2: try to replace each mutated request-packets to origin request-packets

    // std::cout << "Minimal start: " << mid << std::endl;
    std::cout << "Minimal end: " << connections_size << std::endl;

    // check if poc can crash the target
    bool not_crash = true;
    for (auto connection : connections) {
        printf("Current index: %d\n", connection.attribute("round").as_int());
        TestCase testcase = get_request_from_connection(connection);
        try {
            sendAndRecv(testcase);
        } catch (TCPConnectException &e) {
            std::cout << "******** Survival test error ********" << std::endl;
            printf("%s\n", e.what());
            not_crash = false;
        } catch (TCPTimeoutException &e) {
            std::cout << "******** Survival test error ********" << std::endl;
            printf("%s\n", e.what());
            not_crash = false;
        } catch (FuzzerException &e) {
            std::cout << "******** Survival test error ********" << std::endl;
            printf("%s\n", e.what());
            not_crash = false;
        }

        if (connect.getPort() == 631) {
            system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
        }
    }
    std::vector<TcpData> test_resp = testSurvival();
    if (connect.getPort() == 631) {
        system((std::string("ipptool -T 1 -t ipp://") + connect.getAddress() + std::string("/ipp/print /usr/share/cups/ipptool/cancel-current-job.test")).c_str());
    }
    std::vector<std::shared_ptr<Response>> survival_responses = handleResponse(test_resp);
    debug(survival_responses);
    if (!checkSurvivalPath(survival_responses)) {
        std::cout << "******** Survival test failed ********" << std::endl;
        not_crash = false;
    } else {
        std::cout << "-------- Survival test passed --------" << std::endl;
    }

    if (not_crash && snmp_monitor()) {
        std::cout << "PoC can't crash the target" << std::endl;
        return;
    }

    // get end time
    auto end_time = std::chrono::high_resolution_clock::now();
    std::chrono::duration<double> poc_time = end_time - time2;
    std::cout << "PoC time: " << poc_time.count() << "s" << std::endl;


    // restart_device();
    pugi::xml_document poc_xml;
    pugi::xml_node poc_node = poc_xml.append_child("PoC");
    for (auto connection : connections) {
        poc_node.append_copy(connection);
    }
    // save poc_node to a new xml
    std::string buffer = "poc/" + connect.getAddress() + "-" + std::to_string(connect.getPort()) + "/" + std::to_string(target_round) + "-poc.xml";
    std::cout << "Saving PoC: " << poc_xml.save_file(buffer.c_str()) << std::endl;
    std::cout << "Saving path: " << buffer << std::endl;
    std::cout << "Stage 0 time = " << stage0_time.count() << "s" << std::endl;
    std::cout << "Stage 1 time = " << stage1_time.count() << "s" << std::endl;
    std::cout << "PoC time = " << poc_time.count() << "s" << std::endl;
    // write times to time.md file
    std::ofstream file;
    file.open("poc/" + connect.getAddress() + "-" + std::to_string(connect.getPort()) + "/" + std::to_string(target_round) + "-time.md");
    file << "Stage 0 time = " << stage0_time.count() << "s" << std::endl;
    file << "Stage 1 time = " << stage1_time.count() << "s" << std::endl;
    file << "PoC time = " << poc_time.count() << "s" << std::endl;

    file.close();
}

void TCPFuzzer::saveLogHandler() {
    // save log if last_save_timestamp is empty, or if it's been 5 minutes since last save
    auto now = std::chrono::system_clock::now();
    auto timestamp = std::chrono::duration_cast<std::chrono::milliseconds>(now.time_since_epoch()).count();
    if (last_save_timestamp == 0 || timestamp - last_save_timestamp >= 300000) {
        saveLog();
        last_save_timestamp = timestamp;
    }
}

void TCPFuzzer::saveLog() {
    // write result_xml to file
    std::string buffer = log_dir + "log.xml";
    std::cout << "Saving result: " << result_xml.save_file(buffer.c_str()) << std::endl;

    std::ofstream logfd(::log_dir + "fuzz_log.txt", std::ios::app);
    if (!logfd.is_open()) {
        std::cerr << "Can't open log file" << std::endl;
    } else {
        time_t cur_time = std::chrono::system_clock::to_time_t(std::chrono::system_clock::now());
        cur_time -= start_timestamp;
        time_t hours = cur_time / 3600;
        time_t minutes = (cur_time % 3600) / 60;
        time_t seconds = cur_time % 60;

        std::ostringstream formatted;
        formatted << std::setfill('0') << std::setw(2) << hours << ":"
                  << std::setfill('0') << std::setw(2) << minutes << ":"
                  << std::setfill('0') << std::setw(2) << seconds;

        std::string diff_time = formatted.str();

        logfd << std::left << std::setw(20) << diff_time << std::left << std::setw(20) << round << std::left << std::setw(20) << (int)mutate_stage << std::left << std::setw(20) << seed_pool.getCoverage() << std::left << std::setw(20) << all_crash_count << std::endl;
        logfd.close();
    }
}

void TCPFuzzer::endFuzzer() {
    std::cout << "Fuzzer end" << std::endl;
    saveLog();
    exit(EXIT_SUCCESS);
}

void TCPFuzzer::crashHandler(const std::string& crush_msg) {
    std::cout << "[" + getCurrentTime() + "] Crush detected" << std::endl;
    if (need_restart == false) {
        all_crash_count += 1;
    }
    // save round and crush_msg to crush_log.txt
    std::ofstream crush_log(::log_dir + "crash_log.txt", std::ios::app);
    if (!crush_log.is_open()) {
        std::cerr << "Can't open crush log file" << std::endl;
    } else {
        crush_log << std::left << std::setw(20) << round << std::left << std::setw(20) << crush_msg << std::endl;
        crush_log.close();
    }
    current_power = 0;
    // device_controller.restartDevice();
    need_restart = true;
}
