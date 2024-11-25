#include "fuzzer/seed_pool.hpp"

#include <cstdio>
#include <fstream>
#include <iostream>

#include "./utils.hpp"

Seed::Seed() {
    generateFileName();
}

void Seed::setFileName(std::string file_name) {
    this->fileName = file_name;
}

void Seed::generateFileName() {
    this->fileName = getCurrentTime() + ".xml";
}

pugi::xml_document Seed::getFromFile() {
    pugi::xml_document doc = pugi::xml_document();
    pugi::xml_parse_result result = doc.load_file(fileName.c_str());
    if (!result) {
        std::cout << "Error: " << result.description() << std::endl;
        exit(EXIT_FAILURE);
    }
    return doc;
}

bool Seed::saveToFile(const pugi::xml_document &doc) {
    return doc.save_file((::log_dir + "seedpool/" + fileName).c_str());
}

void Seed::saveInputXmlToSeed() {
    std::string filename = ::log_dir + INPUT_FILE_NAME;
    std::string cmd = "cp " + filename + " " + ::log_dir + "seedpool/" + this->fileName;
    system(cmd.c_str());
}

bool SeedPool::seedPoolIsEmpty() {
    return seedPool.empty();
}

void SeedPool::addNewSeed(const std::vector<std::shared_ptr<Response>> &responses) {
    Seed seed;
    seed.responses = responses;
    seed.saveInputXmlToSeed();
    seedPool.push_back(seed);
    // debug(seed);
}

Seed SeedPool::nextSeed() {
    if (seedPool.empty()) {
        std::cerr << "Error: seed pool is empty" << std::endl;
        exit(EXIT_FAILURE);
    }
    Seed seed;
    seed = seedPool.front();
    seedPool.erase(seedPool.begin());
    seedPool.push_back(seed);
    std::string cmd = "cp ";
    cmd += ::log_dir + "seedpool/" + seed.fileName + " ";
    cmd += ::log_dir + INPUT_FILE_NAME;
    system(cmd.c_str());
    return seed;
}

int SeedPool::getCoverage() {
    return seedPool.size();
}

void SeedPool::debug(const Seed &seed) {
    std::string filename = ::log_dir + "seed.txt";
    std::ofstream ofs(filename, std::ios::app);
    ofs << "===================Seed " << getCoverage() << "===================" << std::endl;
    ofs << "Seed file: " << seed.fileName << std::endl
        << std::endl;
    for (const auto& response : seed.responses) {
        ofs << response->to_string() << std::endl;
    }
    ofs.close();
}
