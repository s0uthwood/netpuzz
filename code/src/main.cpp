#include <getopt.h>
#include <unistd.h>

#include <algorithm>
#include <csignal>
#include <cstdlib>
#include <iostream>

#include "./defines.hpp"
#include "./utils.hpp"
#include "fuzzer/ipp_fuzzer.hpp"
#include "fuzzer/lpd_fuzzer.hpp"
#include "fuzzer/tcp_fuzzer.hpp"

enum ProtocolType {
    lpd,
    ipp
};

void help(const char* filename) {
    std::cout << "Usage: " << filename << " [-h] [-p <protocol> | -P <target port>] [-f <template file>] [-x <reference file>] [-c <config file>] [-t <target ip>] [-s <seed>]" << std::endl;
    std::cout << "Version: " << VERSION << ": " << __DATE__ << " " << __TIME__ << std::endl;
    std::cout << "Options:" << std::endl;
    std::cout << "  -h, --help                    Print this help message and exit." << std::endl;
    std::cout << "  -p, --protocol <protocol>     Set protocol type, support: [lpd, ipp]." << std::endl;
    std::cout << "  -f, --file <template file>    Set template xml file." << std::endl;
    std::cout << "  -x, --reference <ref file>    Set reference xml file." << std::endl;
    std::cout << "  -c, --config <config file>    Set config xml file." << std::endl;
    std::cout << "  -t, --target <target ip>      Set target address." << std::endl;
    std::cout << "  -P, --port <target port>      Set target port." << std::endl;
    std::cout << "  -s, --seed <seed>             Set random seed." << std::endl;
    std::cout << "  -l, --log <log file>          Set log file." << std::endl;
    std::cout << "  -a, --start round in log      Set start round in log file." << std::endl;
    std::cout << "  -r, --target round in log     Set target round in log file." << std::endl;
}

TCPFuzzer *fuzzer = nullptr;

static void signalHandler(int signum) {
    if (signum == SIGINT && fuzzer != nullptr) {
        fuzzer->endFuzzer();
    }
}

std::string log_dir = "fuzz_data";
// std::string seedDir;

int main(int argc, char *argv[]) {
    int opt;
    std::string xml_file;
    std::string ref_file;
    std::string config_file;
    std::string log_file;
    std::string targetAddress;
    int targetPort = -1;
    int start_round = 0;
    int target_round = -1;
    srand(time(nullptr));
    unsigned int seed = rand();
    ProtocolType protocol;

    const option longOptions[] = {
        {"help", no_argument, nullptr, 'h'},
        {"protocol", required_argument, nullptr, 'p'},
        {"file", required_argument, nullptr, 'f'},
        {"reference", required_argument, nullptr, 'x'},
        {"config", required_argument, nullptr, 'c'},
        {"target", required_argument, nullptr, 't'},
        {"port", required_argument, nullptr, 'P'},
        {"seed", required_argument, nullptr, 's'},
        {"log", required_argument, nullptr, 'l'},
        {"round", required_argument, nullptr, 'r'},
        {nullptr, 0, nullptr, 0}};

    if (argc == 1) {
        help(argv[0]);
        return 0;
    }

    while ((opt = getopt_long(argc, argv, "hp:f:x:c:t:P:s:l:a:r:", longOptions, nullptr)) != -1) {
        switch (opt) {
        case 'h':
            help(argv[0]);
            return 0;
        case 'p':
            if (toLower(optarg) == "lpd") {
                protocol = ProtocolType::lpd;
                if (targetPort == -1)
                    targetPort = 515;
            } else if (toLower(optarg) == "ipp") {
                protocol = ProtocolType::ipp;
                if (targetPort == -1)
                    targetPort = 631;
            } else {
                std::cout << "Invalid protocol." << std::endl;
                return 1;
            }
            break;
        case 'f':
            xml_file = optarg;
            break;
        case 'x':
            ref_file = optarg;
            break;
        case 'c':
            config_file = optarg;
            break;
        case 't':
            targetAddress = optarg;
            break;
        case 'P':
            targetPort = atoi(optarg);
            break;
        case 's':
            seed = atoi(optarg);
            break;
        case 'l':
            log_file = optarg;
            break;
        case 'a':
            start_round = atoi(optarg);
            break;
        case 'r':
            target_round = atoi(optarg);
            break;
        case '?':
            if (optopt == 'p' || optopt == 'f' || optopt == 's') {
                std::cout << "Option -" << static_cast<char>(optopt) << " requires an argument." << std::endl;
            } else {
                std::cout << "Unknown option -" << static_cast<char>(optopt) << "." << std::endl;
            }
            return 1;
        default:
            help(argv[0]);
            return 1;
        }
    }

    // NOTE: get target address and port from config file if specified
    pugi::xml_document doc = pugi::xml_document();
    pugi::xml_parse_result result = doc.load_file(config_file.c_str());
    if (!result) {
        std::cout << "Error: " << result.description() << std::endl;
    } else {
        targetAddress = doc.child("Target").attribute("ip").value();
    }
    if (targetAddress.empty() || targetPort == -1) {
        std::cout << "Please specify a target address and port." << std::endl;
        help(argv[0]);
        return 1;
    }

    switch (protocol) {
    case ProtocolType::lpd:
        fuzzer = new LPDFuzzer(targetAddress, targetPort, seed);
        break;
    case ProtocolType::ipp:
        fuzzer = new IPPFuzzer(targetAddress, targetPort, seed);
        break;
    default:
        std::cout << "Invalid protocol." << std::endl;
        return 1;
    }

    // NOTE: if config file is specified, initialize device controller
    if (!config_file.empty()) {
        fuzzer->setDeviceController(config_file);
    }

    if (!log_file.empty()) {
        fuzzer->run_poc(log_file, start_round, target_round);
        return 0;
    }

    // NOTE: register signal handler for SIGINT
    signal(SIGINT, signalHandler);

    if (xml_file.empty()) {
        std::cout << "Please specify a template file." << std::endl;
        help(argv[0]);
        return 1;
    }

    log_dir = log_dir + "/" + targetAddress + "-" + std::to_string(targetPort) + "-" + getCurrentTime() + "/";
    std::string mkdir_cmd = "mkdir ";
    mkdir_cmd += log_dir;
    system(mkdir_cmd.c_str());
    mkdir_cmd = "mkdir ";
    mkdir_cmd += log_dir;
    mkdir_cmd += "seedpool";
    system(mkdir_cmd.c_str());

    // NOTE: copy template file and config file to log directory
    try {
        std::string command = std::string("cp ") + xml_file + std::string(" ") + log_dir + INPUT_FILE_NAME;
        system(command.c_str());
        if (!ref_file.empty()) {
            command = std::string("cp ") + ref_file + std::string(" ") + log_dir + REF_FILE_NAME;
            system(command.c_str());
        }
    } catch (std::exception &e) {
        std::cout << "Error: " << e.what() << std::endl;
        return 1;
    }
    std::cout << "Start init" << std::endl;
    fuzzer->init();
    std::cout << "Start run" << std::endl;
    fuzzer->run();
    return 0;
}
