#ifndef INCLUDE_FUZZER_MUTATOR_HPP_
#define INCLUDE_FUZZER_MUTATOR_HPP_

#include <random>
#include <string>
#include <vector>

#include "./defines.hpp"
#include "./xml_extension.hpp"

struct case_prob {
    std::string value;
    double weight;
};

class Mutator {
 public:
    Mutator();
    explicit Mutator(u32 seed);

    pugi::xml_node selectRandChild(const pugi::xml_node &node);
    pugi::xml_node selectRandLeaf(const pugi::xml_node &node);
    pugi::xml_node selectRandNode(const pugi::xml_node &node);

    bool mutateRandValue(pugi::xml_node &node);
    void mutateBlockChild(pugi::xml_node &node);

    bool dupRandChild(pugi::xml_node &root);
    bool deleteRandChild(pugi::xml_node &root);
    bool swapRandChildren(pugi::xml_node &root);

    bool dupNodeToRandLocation(pugi::xml_node &node);
    bool swapRandNearNode(pugi::xml_node &node);
    bool deleteCurrentNode(pugi::xml_node &node);
    bool mutatePacketDelay(pugi::xml_node &packet_node);

    void readReference(std::string reference_dir);
    bool checkReference();

    void setDebugMode();

 private:
    enum class DataMutation {
        FLIP,
        ARITHMETIC,
        SWAP,
        DELETE,
        DUPLICATE,
        INSERT,
        OVERFLOW,
        MUTATION_COUNT
    };
    enum class BlockMutation {
        SWAP,
        DELETE,
        DUPLICATE,
        MUTATION_COUNT
    };

    DataMutation mutateDataNode(pugi::xml_node node);
    DataMutation mutateSizeNode(pugi::xml_node node);
    DataMutation mutateChecksumNode(pugi::xml_node node);

    void updateAllSize(pugi::xml_node node);
    void updateSizeNode(pugi::xml_node node);
    void updateAllChecksum(pugi::xml_node node);

    bool mutateNodeByReference(pugi::xml_node node, pugi::xml_node ref_node);
    bool findParaInReference(pugi::xml_node node, pugi::xml_node& ref_node);
    bool isPacketIdMeet(pugi::xml_node packet_node, pugi::xml_node ref_packet_node);

    bool have_reference = false;
    pugi::xml_document reference_doc;
    XmlExtension xml_extension;

    class RandomGenerator {
     public:
        RandomGenerator();
        explicit RandomGenerator(unsigned int seed);

        size_t generateSizeT(size_t min, size_t max);
        int generateRandomWithWeight(const std::vector<double> &weights);
        std::string chooseRandomWithWeight(const std::vector<std::string> &choices, const std::vector<double> &weights);
        u32 getSeed() const;

     private:
        std::random_device rd;
        std::mt19937 gen;
        u32 seed;
    };
    RandomGenerator *rng;

    bool debug_mode = false;
};

#endif  // INCLUDE_FUZZER_MUTATOR_HPP_
