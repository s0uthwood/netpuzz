#ifndef INCLUDE_FUZZER_DEVICE_CONTROLLER_HPP_
#define INCLUDE_FUZZER_DEVICE_CONTROLLER_HPP_

#include <regex>
#include <string>
#include <vector>

struct DeviceController {
    struct SwitchCommand {
        std::string cmd;
        int delay_time;
    };
    int restart_round = -1;
    SwitchCommand off_cmd;
    SwitchCommand on_cmd;

    bool getSwCmdFromXml(const std::string& fileName);
    bool restartDevice();

    enum class MonitorMode {
        MATCH_MODE,
        INCREASE_MODE
    };

    struct MonitorCommand {
        std::string cmd;
        std::regex pattern;
        MonitorMode mode;
        std::string response;  // match mode
        int last_response;     // increase mode
    };
    std::vector<MonitorCommand> monitor_cmd;

    bool getMonitorCmdFromXml(const std::string& filename);
    int monitorDevice();

    std::string getResOfCommand(const MonitorCommand& command);
};

#endif  // INCLUDE_FUZZER_DEVICE_CONTROLLER_HPP_
