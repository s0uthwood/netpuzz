#ifndef INCLUDE_FUZZER_TCP_FUZZER_HPP_
#define INCLUDE_FUZZER_TCP_FUZZER_HPP_

#include <unistd.h>

#include <ctime>
#include <string>
#include <vector>
#include <atomic>
#include <iostream>

#include "./xml_extension.hpp"
#include "fuzzer/device_controller.hpp"
#include "fuzzer/mutator.hpp"
#include "fuzzer/response.hpp"
#include "fuzzer/seed_pool.hpp"
#include "fuzzer/tcp_connect.hpp"
#include "fuzzer/test_case.hpp"

#define MUTATION_TIMES 10
#define MAX_MUTATION_COUNT 6
#define SLEEP_UTIME 500000

extern std::string log_dir;

class FuzzerException : public std::exception {
 public:
    explicit FuzzerException(const std::string &message) :
        message(message) {
    }
    const char *what() const noexcept override {
        return message.c_str();
    }

 private:
    std::string message;
};

class TCPFuzzer;

struct ThreadArgs {
    TCPFuzzer *fuzzer;
    TestCase *testCase;
    std::vector<TcpData> *response;
    pthread_t *sendThread, *recvThread;
    std::atomic<bool> *sendThreadEnd, *recvThreadEnd;
};

class TCPFuzzer {
 public:
    TCPFuzzer(const std::string &address, int port, unsigned int seed);

    void setConnectAddress(const std::string &address, int port);
    bool connectToServer();
    void closeConnection();

    void setOriginTestCase(const TestCase &testCase);
    void setFuzzedTestCase();
    TestCase getOriginTestCase();
    bool mutateInputXml();
    TestCase getTestcaseFromInputXml();

    virtual void setSeedPoolProtocol();

    virtual std::vector<std::shared_ptr<Response>> handleResponse(std::vector<TcpData> response);
    virtual bool isValidRequest(std::vector<std::shared_ptr<Response>> responses);
    virtual bool isInteresting(std::vector<std::shared_ptr<Response>> responses);
    virtual bool checkSurvivalPath(std::vector<std::shared_ptr<Response>> responses);
    virtual TcpData responseFilter(TcpData response);

    bool setDeviceController(const std::string& filename);

    virtual std::vector<TcpData> sendAndRecv(TestCase &testCase);
    std::vector<TcpData> testSurvival();

    void init();
    void run();

    TestCase get_request_from_connection(const pugi::xml_node& connection_node);
    void restart_device();
    bool snmp_monitor();
    void run_poc(const std::string& filename, int start_round, int target_round);
    void saveLogHandler();
    void saveLog();
    void endFuzzer();
    void crashHandler(const std::string& crush_msg);

 protected:
    TCPConnect connect;

    TestCase origin_testcase;
    TestCase fuzzed_testcase;
    std::vector<TcpData> origin_response;

    Mutator mutator;
    SeedPool seed_pool;
    enum class MutateStage {
        STAGE_1,
        STAGE_2,
        STAGE_3,
        STAGE_COUNT
    };

    MutateStage mutate_stage;

    DeviceController device_controller;

    size_t round;
    size_t last_restart_round;
    size_t last_seed_round;
    int current_power;
    std::time_t start_timestamp;
    std::time_t last_save_timestamp;
    pugi::xml_document result_xml;
    pugi::xml_node log_node;

    int all_crash_count;
    bool need_restart;

    static void *sendTestCaseWrapper(void *arg) {
        auto *args = (ThreadArgs *)arg;
        args->fuzzer->sendTestCase(*(args->testCase));
        args->sendThreadEnd->store(true);
        return nullptr;
    }
    void sendTestCase(TestCase &testCase);

    static void *recvResponseWrapper(void *arg) {
        auto *args = (ThreadArgs *)arg;
        args->fuzzer->recvResponse(*(args->response));
        args->recvThreadEnd->store(true);
        return nullptr;
    }
    void recvResponse(std::vector<TcpData> &response);
};

#endif  // INCLUDE_FUZZER_TCP_FUZZER_HPP_
