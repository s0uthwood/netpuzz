#include "fuzzer/device_controller.hpp"

#include <unistd.h>

#include <iostream>

#include "./utils.hpp"
#include "pugixml/pugixml.hpp"

bool DeviceController::getSwCmdFromXml(const std::string& fileName) {
    pugi::xml_document doc = pugi::xml_document();
    pugi::xml_parse_result result = doc.load_file(fileName.c_str());

    if (!result) {
        std::cout << "Error: " << result.description() << std::endl;
        return false;
    }

    pugi::xml_node switch_node = doc.child("Target").child("Switch");
    if (!switch_node) {
        std::cout << "Error: Switch node not found" << std::endl;
        return false;
    }

    if (switch_node.attribute("round")) {
        std::string restart_str = switch_node.attribute("round").value();
        restart_round = std::stoi(restart_str);
    }

    if (switch_node.child("off")) {
        off_cmd.cmd = switch_node.child("off").attribute("cmd").value();
        std::string delay_str = switch_node.child("off").attribute("delay").value();
        off_cmd.delay_time = std::stoi(delay_str);
    }
    if (switch_node.child("on")) {
        on_cmd.cmd = switch_node.child("on").attribute("cmd").value();
        std::string delay_str2 = switch_node.child("on").attribute("delay").value();
        on_cmd.delay_time = std::stoi(delay_str2);
    }
    return true;
}

bool DeviceController::restartDevice() {
    if (restart_round == -1) {
        return false;
    }

    int tmp_cnt = 0;
    while (true) {
        try {
            if (!off_cmd.cmd.empty()) {
                std::cout << "Executing command: " << off_cmd.cmd << std::endl;
                std::string res = ::executeCommand(off_cmd.cmd.c_str());
                // find if "'code': 0" in res
                // std::cout << res << std::endl;
                if (res.find("\'code\': 0") == std::string::npos) {
                    throw std::runtime_error("Error: Command failed.");
                }
                std::cout << "Waiting for " << off_cmd.delay_time << " seconds" << std::endl;
                sleep(off_cmd.delay_time);
            }
            if (!on_cmd.cmd.empty()) {
                std::cout << "Executing command: " << on_cmd.cmd << std::endl;
                std::string res = ::executeCommand(on_cmd.cmd.c_str());
                // std::cout << res << std::endl;
                // find if "'code': 0" in res
                if (res.find("\'code\': 0") == std::string::npos) {
                    throw std::runtime_error("Error: Command failed.");
                }
                std::cout << "Waiting for " << on_cmd.delay_time << " seconds" << std::endl;
                sleep(on_cmd.delay_time);
            }
            break;
        } catch (std::runtime_error &e) {
            if (++tmp_cnt >= 5) {
                std::cout << "Error when restart device, continue or not? ([y]es/[n]o/[N]ever): ";
                char c = getchar();
                std::cout << std::endl;
                switch (c) {
                case 'N':
                    restart_round = -1;
                case 'n':
                    return false;
                case 'y':
                default:
                    tmp_cnt = 0;
                    continue;
                }
            }
        }
    }

    for (int i = 0; i < monitor_cmd.size(); i++) {
        if (monitor_cmd[i].mode == MonitorMode::INCREASE_MODE) {
            std::string res;
            for (int j = 0; j < 5; j++) {
                res = getResOfCommand(monitor_cmd[i]);
                if (res != "") {
                    break;
                }
                std::cout << "Error: Monitor command failed." << std::endl;
                sleep(1);
            }
            if (res != "") {
                monitor_cmd[i].last_response = std::stoi(res);
            } else {
                restartDevice();
                break;
            }
        } else if (monitor_cmd[i].mode == MonitorMode::MATCH_MODE) {
            std::string res;
            for (int j = 0; j < 5; j++) {
                res = getResOfCommand(monitor_cmd[i]);
                if (res == monitor_cmd[i].response) {
                    break;
                }
                std::cout << "Error: Monitor command failed." << std::endl;
                sleep(1);
            }
            if (res == "") {
                restartDevice();
                break;
            }
        }
    }

    return true;
}

bool DeviceController::getMonitorCmdFromXml(const std::string& filename) {
    pugi::xml_document doc = pugi::xml_document();
    pugi::xml_parse_result result = doc.load_file(filename.c_str());

    if (!result) {
        std::cout << "Error: " << result.description() << std::endl;
        return false;
    }
    pugi::xml_node target_node = doc.child("Target");
    pugi::xml_node monitor_node = target_node.child("Monitor");
    if (!monitor_node) {
        std::cout << "Error: Monitor node not found" << std::endl;
        return false;
    }

    for (pugi::xml_node node : target_node.children("Monitor")) {
        MonitorCommand cur_cmd;
        cur_cmd.cmd = node.child("Command").attribute("command").value();
        std::string mode_str = node.child("Command").attribute("mode").value();
        cur_cmd.pattern = std::regex(node.child("Command").attribute("regex").value());
        if (mode_str == "match") {
            cur_cmd.mode = MonitorMode::MATCH_MODE;
            cur_cmd.response = node.child("Command").attribute("response").value();
        } else if (mode_str == "increase") {
            cur_cmd.mode = MonitorMode::INCREASE_MODE;
            std::string res = getResOfCommand(cur_cmd);
            std::cout << "Initial Result: " << res << std::endl;
            if (res.empty()) {
                std::cout << "Error: Monitor command failed." << std::endl;
            } else {
                cur_cmd.last_response = std::stoi(res);
            }
        }
        monitor_cmd.push_back(cur_cmd);
    }

    return true;
}

int DeviceController::monitorDevice() {
    for (int i = 0; i < monitor_cmd.size(); i++) {
        std::string res;
        res = getResOfCommand(monitor_cmd[i]);
        if (res.empty()) {
            return 0;
        }
        if (monitor_cmd[i].mode == MonitorMode::MATCH_MODE) {
            if (res != monitor_cmd[i].response) {
                std::cout << "Size: " << res.size() << std::endl;
                std::cout << "Result: " << res << std::endl;
                std::cout << "Size: " << monitor_cmd[i].response.size() << std::endl;
                std::cout << "Target: " << monitor_cmd[i].response << std::endl;
                return -1;
            }
        } else if (monitor_cmd[i].mode == MonitorMode::INCREASE_MODE) {
            int result = std::stoi(res);
            if (result < monitor_cmd[i].last_response) {
                monitor_cmd[i].last_response = result;
                return -1;
            }
        }
    }
    return 1;
}

std::string DeviceController::getResOfCommand(const MonitorCommand& command) {
    std::string res;
    try {
        res = ::executeCommand(command.cmd);
    } catch (std::runtime_error &e) {
        std::cout << "Error: " << e.what() << std::endl;
        return "";
    }
    std::smatch matches;
    std::string matched_res;
    if (std::regex_search(res, matches, command.pattern)) {
        matched_res = matches[1];
    } else {
        std::cout << "No match found." << std::endl;
        matched_res = "";
    }
    return matched_res;
}
