#ifndef INCLUDE_FUZZER_SEED_POOL_HPP_
#define INCLUDE_FUZZER_SEED_POOL_HPP_

#include <string>
#include <vector>

#include "fuzzer/response.hpp"
#include "fuzzer/test_case.hpp"

extern std::string log_dir;

struct Seed {
    std::string fileName;
    std::vector<std::shared_ptr<Response>> responses;

    Seed();

    void setFileName(std::string fileName);
    void generateFileName();
    pugi::xml_document getFromFile();
    bool saveToFile(const pugi::xml_document &doc);
    void saveInputXmlToSeed();
};

struct SeedPool {
    std::vector<Seed> seedPool;
    std::string protocol;

    SeedPool() :
        seedPool(), protocol() {
    }

    bool seedPoolIsEmpty();
    void addNewSeed(const std::vector<std::shared_ptr<Response>> &response);
    Seed nextSeed();
    int getCoverage();

    // NOTE: temporary function
    void debug(const Seed &seed);
};

#endif  // INCLUDE_FUZZER_SEED_POOL_HPP_
