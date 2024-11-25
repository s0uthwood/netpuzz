#include "fuzzer/mutator.hpp"

#include <cctype>
#include <filesystem>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>

#include "./defines.hpp"
#include "./utils.hpp"

Mutator::Mutator() :
    rng(new RandomGenerator()) {
}

Mutator::Mutator(u32 seed) :
    rng(new RandomGenerator(seed)) {
}

void Mutator::readReference(std::string reference_dir) {
    std::ostringstream oss;
    /*
        Check if reference.xml exists
    */
    if (!std::filesystem::exists(reference_dir)) {
        std::cout << reference_dir << " doesn't exist\n";
        return;
    }

    std::cout << "Find " << reference_dir << std::endl;
    have_reference = true;

    /*
        Parsing reference.xml with entities
    */
    std::cout << "==========================================\n";
    std::cout << "            Parsing reference             \n";
    std::cout << "==========================================\n";
    std::cout << "Replacing entities...\n";

    reference_doc = xml_extension.loadXmlWithEntities(reference_dir);

    have_reference = checkReference();
}

/* check format of reference.xml file */
bool Mutator::checkReference() {
    // Check format of reference.xml
    std::cout << "Checking reference format..." << std::endl;

    // Root node must be a Reference node
    pugi::xml_node reference_node = reference_doc.child("Reference");
    if (!reference_node) {
        std::cerr << "reference.xml's root node must be \"Reference\"\n";
        exit(EXIT_FAILURE);
    }

    return true;
}

bool Mutator::mutateRandValue(pugi::xml_node &node) {
    // Select a random packet and data
    pugi::xml_node selected_node;

    if (node.first_child() == nullptr) {
        selected_node = node;
    } else {
        do {
            selected_node = selectRandLeaf(node);
            if (selected_node == node) {
                return false;
            }
        } while (selected_node.attribute("mutable") && std::string(selected_node.attribute("mutable").as_string()) == "false");
    }

    if (debug_mode) {
        std::cout << "\n\n\n===========================================\n";
        std::cout << "                  Selected                 \n";
        std::cout << "===========================================\n";
        xml_extension.printNode(selected_node);
    }

    pugi::xml_node refer_para_node;
    bool find_para = false;
    // Try to find it in reference.xml
    if (selected_node.attribute("type")) {
        // find the selected_node in reference.xml by type
        find_para = findParaInReference(selected_node, refer_para_node);
    }
    if (find_para && refer_para_node) {
        std::cout << "Found reference:\n";
        if (mutateNodeByReference(selected_node, refer_para_node)) {
            updateAllSize(selected_node);
            updateAllChecksum(selected_node);
            return true;
        }
    }

    std::string node_name = selected_node.name();
    if (node_name == "Data") {
        DataMutation action = mutateDataNode(selected_node);
        if (action == DataMutation::MUTATION_COUNT) {
            return false;
        }
        if (action == DataMutation::DELETE || action == DataMutation::DUPLICATE || action == DataMutation::INSERT) {
            updateAllSize(selected_node);
        }
        updateAllChecksum(selected_node);
    } else if (node_name == "Size") {
        std::cout << "mutateRandValue(): mutate size" << std::endl;
        DataMutation action = mutateSizeNode(selected_node);
        if (action == DataMutation::MUTATION_COUNT) {
            return false;
        }
        updateAllSize(selected_node);
        updateAllChecksum(selected_node);
    } else if (node_name == "Checksum") {
        // mutateChecksumNode(selected_node);
        // updateAllChecksum(selected_node);
    } else {
        std::cout << "mutateRandValue(): unknown node name: " << node_name << std::endl;
    }
    return true;
}

void Mutator::mutateBlockChild(pugi::xml_node &node) {
    std::string node_name = node.name();
    auto action = (BlockMutation)rng->generateSizeT(0, static_cast<int>(BlockMutation::MUTATION_COUNT) - 1);
    switch (action) {
    case BlockMutation::SWAP:
        swapRandChildren(node);
        break;
    case BlockMutation::DELETE:
        deleteRandChild(node);
        break;
    case BlockMutation::DUPLICATE:
        dupRandChild(node);
        break;
    default:
        std::cerr << "mutateBlockChild(): unknown action" << std::endl;
        exit(EXIT_FAILURE);
    }
}

bool Mutator::dupNodeToRandLocation(pugi::xml_node &node) {
    if (std::string(node.name()) == "Sequence") {
        std::cout << "dupNode(): can't duplicate Sequence node\n";
        return false;
    }

    // get random location for new node
    pugi::xml_node parent = node.parent();
    pugi::xml_node new_location_node = selectRandChild(parent);

    node.parent().insert_copy_after(node, new_location_node);
    return true;
}

bool Mutator::dupRandChild(pugi::xml_node &root) {
    if (root.first_child() == nullptr) {
        std::cout << "addRandPacket(): no child can choose\n";
        return false;
    }

    // selete a random child node to duplicate
    pugi::xml_node selected_node = selectRandChild(root);
    pugi::xml_node copy_of_selected_node = selected_node;

    // get random location for new node
    pugi::xml_node new_location_node = selectRandChild(root);

    root.insert_copy_after(copy_of_selected_node, new_location_node);
    return true;
}

bool Mutator::deleteRandChild(pugi::xml_node &root) {
    if (root.first_child() == nullptr) {
        std::cout << "deleteRandPacket(): no child can choose\n";
        return false;
    }

    pugi::xml_node selected_node = selectRandChild(root);

    root.remove_child(selected_node);
    return true;
}

bool Mutator::swapRandChildren(pugi::xml_node &root) {
    // Check if there are at least two children
    if (root.first_child() == nullptr || root.first_child().next_sibling() == nullptr) {
        std::cout << "swapRandPacket(): must have at least 2 child\n";
        return false;
    }

    pugi::xml_node first_node, second_node;
    do {
        first_node = selectRandChild(root);
        second_node = selectRandChild(root);
    } while (first_node == second_node);  // Ensure they are different

    // Create copies of the nodes
    pugi::xml_node first_node_copy = first_node;
    pugi::xml_node second_node_copy = second_node;

    // Swap the nodes
    root.insert_copy_before(first_node_copy, second_node);
    root.insert_copy_after(second_node_copy, first_node);
    root.remove_child(first_node);
    root.remove_child(second_node);

    return true;
}

/*
 * This mutator is utilized to swap the current node
 * with a randomly selected node within the same parent and at same depth.
 */
bool Mutator::swapRandNearNode(pugi::xml_node &node) {
    // Get the parent of current node
    std::string node_name = node.name();
    if (node_name == "Sequence") {
        std::cout << "swapRandNearNode(): can't swap Sequence node\n";
        return false;
    }

    // Check if there are at least two children in parent
    pugi::xml_node root = node.parent();
    if (root.first_child() == nullptr || root.first_child().next_sibling() == nullptr) {
        std::cout << "swapRandNearNode(): must have at least 2 child\n";
        return false;
    }

    pugi::xml_node other_node;
    do {
        other_node = selectRandChild(root);
    } while (other_node == node);  // Ensure they are different

    // Create copies of the nodes
    pugi::xml_node first_node_copy = node;
    pugi::xml_node second_node_copy = other_node;

    // Swap the nodes
    node.insert_copy_before(first_node_copy, other_node);
    node.insert_copy_after(second_node_copy, node);
    node.remove_child(node);
    node.remove_child(other_node);

    return true;
}

bool Mutator::mutatePacketDelay(pugi::xml_node &packet_node) {
    if (packet_node.attribute("mutable").as_string() == std::string("false")) {
        return false;
    }

    std::string delay_str = packet_node.attribute("delay").as_string();
    // delay_str may have space
    u32 delay = static_cast<u32>(parseHexStringAsLittleEndian(delay_str, (delay_str.length() + 1) / 3));
    if (packet_node.attribute("diff")) {
        delay += packet_node.attribute("diff").as_int();
    }
    int rand_max = 2 * delay;
    int rand_min = delay / 2;
    if (rand_min > rand_max) {
        int tmp = rand_min;
        rand_min = rand_max;
        rand_max = tmp;
    } else if (rand_min == rand_max) {
        rand_max += 1;
    }
    int rand = rng->generateSizeT(rand_min, rand_max);
    if (rand < MIN_DELAY) {
        rand = MIN_DELAY - 1;
    } else if (rand > MAX_DELAY) {
        rand = MAX_DELAY + 1;
    }
    int diff = rand - static_cast<int>(delay);
    packet_node.attribute("diff").set_value(diff);
    return true;
}

pugi::xml_node Mutator::selectRandChild(const pugi::xml_node &node) {
    std::vector<pugi::xml_node> child_nodes;

    xml_extension.getChildNodes(node, child_nodes);

    if (child_nodes.empty()) {
        return node;
    }

    return child_nodes[rng->generateSizeT(0, child_nodes.size() - 1)];
}

pugi::xml_node Mutator::selectRandLeaf(const pugi::xml_node &node) {
    std::vector<pugi::xml_node> leaf_nodes;

    xml_extension.getAllLeafNodes(node, leaf_nodes);

    if (leaf_nodes.empty()) {
        std::cerr << "selectRandLeaf(): this node has no leaf\n";
        return node;
    }

    return leaf_nodes[rng->generateSizeT(0, leaf_nodes.size() - 1)];
}

pugi::xml_node Mutator::selectRandNode(const pugi::xml_node &node) {
    std::vector<pugi::xml_node> nodes;

    xml_extension.getAllNodes(node, nodes);

    if (nodes.empty()) {
        std::cerr << "selectRandNode(): this node has no node\n";
        exit(EXIT_FAILURE);
    }

    return nodes[rng->generateSizeT(0, nodes.size() - 1)];
}

Mutator::DataMutation Mutator::mutateDataNode(pugi::xml_node node) {
    if (node.attribute("mutable").as_string() == std::string("false")) {
        return DataMutation::MUTATION_COUNT;
    }

    std::vector<u8> data;
    xml_extension.getNodeValue(node, data);
    size_t rand_index, rand_index_2, overflow_times, original_size;
    int rand;
    DataMutation action = (DataMutation)rng->generateSizeT(0, (int)DataMutation::MUTATION_COUNT - 1);
    if (data.size() == 0) {
        action = DataMutation::INSERT;
    }
    switch (action) {
    case DataMutation::FLIP:
        // flip a bit
        rand_index = rng->generateSizeT(0, data.size() - 1);
        data[rand_index] ^= 1 << rng->generateSizeT(0, 7);
        break;
    case DataMutation::ARITHMETIC:
        // add or sub a random number
        rand = rng->generateSizeT(0, 2 * ARITH_MAX);
        rand -= ARITH_MAX;
        rand_index = rng->generateSizeT(0, data.size() - 1);
        data[rand_index] += rand;
        break;
    case DataMutation::SWAP:
        // swap two bytes
        rand_index = rng->generateSizeT(0, data.size() - 1);
        rand_index_2 = rng->generateSizeT(0, data.size() - 1);
        std::swap(data[rand_index], data[rand_index_2]);
        break;
    case DataMutation::DELETE:
        // delete a byte
        if (data.size() == 0) {
            // can't delete the last byte
            return DataMutation::MUTATION_COUNT;
        }
        rand_index = rng->generateSizeT(0, data.size() - 1);
        data.erase(data.begin() + rand_index);
        break;
    case DataMutation::DUPLICATE:
        // duplicate a byte
        rand_index = rng->generateSizeT(0, data.size() - 1);
        data.insert(data.begin() + rand_index, data[rand_index]);
        break;
    case DataMutation::INSERT:
        rand_index = rng->generateSizeT(0, data.size());
        data.insert(data.begin() + rand_index, rng->generateSizeT(0, 0xFF));
        break;
    case DataMutation::OVERFLOW:
        overflow_times = 1 << rng->generateSizeT(3, 11);
        original_size = data.size();
        if (original_size * overflow_times > 1025) {
            break;
        }
        data.resize(original_size * overflow_times);
        for (int i = 0; i < overflow_times - 1; i++) {
            std::copy(data.begin(), data.begin() + original_size, data.begin() + i * original_size);
        }
        break;
    default:
        std::cerr << "mutateDataNode(): unknown action" << std::endl;
        //exit(EXIT_FAILURE);
    }
    // std::cout << "mutateDataNode(): mutated size: " << data.size() << std::endl;
    if (data.size() == 0) {
        std::cout << "mutateDataNode(): mutated to empty" << std::endl;
        node.attribute("value").set_value("");
    } else {
        std::string mutated_str(data.begin(), data.end());
        std::cout << "mutateDataNode(): mutated to: " << mutated_str << std::endl;
        std::string mutated_hex = stringToHex(mutated_str);
        std::cout << "mutated_hex: " << mutated_hex << std::endl;
        node.attribute("value").set_value(mutated_hex.c_str(), mutated_hex.size());
    }
    return action;
}

Mutator::DataMutation Mutator::mutateSizeNode(pugi::xml_node node) {
    if (node.attribute("mutable").as_string() == std::string("false")) {
        return DataMutation::MUTATION_COUNT;
    } else {
        // Size node can only mutate arithmetic
        int rand = rng->generateSizeT(0, 2 * ARITH_MAX);
        rand -= ARITH_MAX;
        if (rand == 0) {
            rand += 1;
        }
        if (node.attribute("diff")) {
            rand += node.attribute("diff").as_int();
            node.attribute("diff").set_value(rand);
        } else {
            node.append_attribute("diff") = rand;
        }
        std::cout << "mutateSizeNode(): mutated to: " << rand << std::endl;
        return DataMutation::ARITHMETIC;
    }
}

void Mutator::updateAllSize(pugi::xml_node node) {
    // find all size node from current node
    pugi::xml_node root = node;
    // find the root node
    std::string root_name = root.name();
    while (root_name != std::string("Sequence")) {
        root = root.parent();
        root_name = root.name();
    }
    std::vector<pugi::xml_node> size_nodes;
    xml_extension.getAllNodesByNameInPostOrder(root, "Size", size_nodes);

    // update size node with order in size_nodes
    for (pugi::xml_node size_node : size_nodes) {
        updateSizeNode(size_node);
    }
}

void Mutator::updateSizeNode(pugi::xml_node node) {
    // assemble the data from ref attributes
    std::vector<std::string> ref_attributes = splitString(node.attribute("ref").as_string(), '.');
    // find the relation node from root
    pugi::xml_node root = node;
    std::string root_name = root.name();
    while (root_name != std::string("Sequence")) {
        root = root.parent();
        root_name = root.name();
    }
    pugi::xml_node relation_node = root;
    // This node is used when relation is delated
    pugi::xml_node empty_node;
    for (const std::string& ref_attribute : ref_attributes) {
        for (pugi::xml_node child : relation_node.children()) {
            if (!child.attribute("name")) {
                continue;
            }
            if (child.attribute("name").as_string() == ref_attribute) {
                relation_node = child;
                break;
            }
        }
        if (!relation_node.attribute("name")) {
            std::cerr << "updateSizeNode(): can't find relation node: " << node.attribute("ref").as_string() << std::endl;
            // exit(EXIT_FAILURE);
            relation_node = empty_node;
        } else if (relation_node.attribute("name").as_string() != ref_attribute) {
            std::cerr << "updateSizeNode(): can't find relation node: " << node.attribute("ref").as_string() << std::endl;
            // exit(EXIT_FAILURE);
            relation_node = empty_node;
        }
    }

    std::vector<u8> relation_data;
    xml_extension.assembleNodes(relation_node, relation_data);
    int relation_size = relation_data.size();
    if (!node.attribute("valueType")) {
        std::cerr << "updateSizeNode(): can't find valueType attribute\n";
        exit(EXIT_FAILURE);
    }
    std::string node_value_type = node.attribute("valueType").as_string();
    int diff = 0;
    if (node.attribute("diff")) {
        diff = node.attribute("diff").as_int();
    }
    relation_size += diff;
    if (node_value_type == "byte") {
        std::vector<u8> relation_size_bytes;
        bool little_endian = false;
        if (node.attribute("endian").as_string() == std::string("big")) {
            little_endian = false;
        } else if (node.attribute("endian").as_string() == std::string("little")) {
            little_endian = true;
        } else {
            std::cerr << "updateSizeNode(): can't find endian attribute\n";
        }
        u64ToBytes(relation_size, node.attribute("len").as_int(), little_endian, relation_size_bytes);
        std::string relation_size_str(relation_size_bytes.begin(), relation_size_bytes.end());
        std::string relation_size_hex = stringToHex(relation_size_str);
        node.attribute("value").set_value(relation_size_hex.c_str(), relation_size_hex.size());
    } else if (node_value_type == "hex") {
        // convert int to hexstring
        std::string relation_size_hexstr = u64ToHexString(relation_size, "lower");
        // convert hexstring to hex
        std::string relation_size_hex = stringToHex(relation_size_hexstr);
        node.attribute("value").set_value(relation_size_hex.c_str(), relation_size_hex.size());
    } else if (node_value_type == "string") {
        // convert int to string
        std::string relation_size_str = std::to_string(relation_size);
        // convert string to hex
        std::string relation_size_hex = stringToHex(relation_size_str);
        node.attribute("value").set_value(relation_size_hex.c_str(), relation_size_hex.size());
    } else {
        std::cerr << "updateSizeNode(): unknown valueType: " << node_value_type << std::endl;
        exit(EXIT_FAILURE);
    }
}

void Mutator::updateAllChecksum(pugi::xml_node node) {
    // TODO
}

bool Mutator::mutateNodeByReference(pugi::xml_node node, pugi::xml_node ref_node) {
    std::string mutation_type = ref_node.attribute("mutation").as_string();
    if (mutation_type == "range") {
        int para_len = ref_node.attribute("len").as_int();

        u64 min_val = parseHexStringAsLittleEndian(ref_node.attribute("min").as_string(), para_len);
        u64 max_val = parseHexStringAsLittleEndian(ref_node.attribute("max").as_string(), para_len);
        u64 origin_val = parseHexStringAsLittleEndian(node.attribute("value").as_string(), para_len);

        u64 range_size = max_val - min_val + 1;
        std::vector<double> probabilities(range_size, 0.0);
        double rest_prob = 1.0;
        u64 weight_num = 0;

        for (pugi::xml_node weight_node : ref_node.children("Weight")) {
            u64 case_val = parseHexStringAsLittleEndian(weight_node.attribute("case").as_string(), para_len);

            double weight_val = weight_node.text().as_double();
            probabilities[case_val - min_val] = weight_val;
            rest_prob = rest_prob - weight_val;
            weight_num++;
        }

        double average_rest_prob = rest_prob / (range_size - weight_num);
        for (double &prob : probabilities) {
            if (prob == 0.0) {
                prob = average_rest_prob;
            }
        }

        // Set origin_val's probability as zero
        double sum_of_remaining_probabilities = 1.0 - probabilities[origin_val - min_val];
        probabilities[origin_val - min_val] = 0.0;
        // Re-nomalize
        for (double &prob : probabilities) {
            if (prob != 0.0) {
                prob /= sum_of_remaining_probabilities;
            }
        }

        u64 mutated_value = rng->generateRandomWithWeight(probabilities) + min_val;
        std::vector<u8> mutated_vec;
        u64ToBytes(mutated_value, para_len, true, mutated_vec);
        std::string mutated_str(mutated_vec.begin(), mutated_vec.end());
        std::string mutated_hex = stringToHex(mutated_str);
        node.attribute("value").set_value(mutated_hex.c_str(), mutated_hex.size());
    } else if (mutation_type == "case") {
        double total_weight = 0.0;
        int total_case = 0;
        std::vector<std::string> cases;
        std::vector<double> weight;
        std::string current_value = node.attribute("value").as_string();
        transform(current_value.begin(), current_value.end(), current_value.begin(), ::tolower);
        for (pugi::xml_node case_node : ref_node.children("case")) {
            std::string current_case = case_node.attribute("value").as_string();
            transform(current_case.begin(), current_case.end(), current_case.begin(), ::tolower);
            if (current_case == current_value) {
                continue;
            }
            cases.push_back(current_case);
            weight.push_back(case_node.attribute("weight").as_double());

            total_weight += weight.back();
            total_case++;
        }

        // std::vector<double> weights;
        for (int i = 0; i < static_cast<int>(weight.size()); i++) {
            weight[i] /= total_weight;
        }
        if (total_case == 0) {
            return false;
        }
        std::string mutated_str = rng->chooseRandomWithWeight(cases, weight);
        node.attribute("value").set_value(mutated_str.c_str(), mutated_str.size());
    } else {
        return false;
    }
    return true;
}

bool Mutator::findParaInReference(pugi::xml_node node, pugi::xml_node &ref_node) {
    // find Packet type of the node
    std::vector<std::string> type_path;
    type_path.push_back(node.attribute("type").as_string());
    std::string packet_type;
    std::string parent_name = node.parent().name();
    pugi::xml_node parent_node = node;
    while (parent_name != "Packet") {
        parent_node = parent_node.parent();
        type_path.push_back(parent_node.attribute("type").as_string());
        // if node has no parent, return false
        if (parent_node.parent().empty()) {
            // std::cerr << "findParaInReference(): node has no Packet parent\n" << std::endl;
            return false;
        }
        parent_name = parent_node.parent().name();
    }
    parent_node = parent_node.parent();
    packet_type = parent_node.attribute("type").as_string();
    // std::cout << "findParaInReference(): node: " << type_path << std::endl;
    // std::cout << "findParaInReference(): packet: " << packet_type << std::endl;

    // seek all type in type_path
    for (int i = 0; i < type_path.size(); i++) {
        // seek in all PacketSeries
        std::string cur_type = type_path[i];
        pugi::xml_node packet_series;
        for (pugi::xml_node ref_packet_node : reference_doc.child("Reference").children("PacketSeries")) {
            if (ref_packet_node.attribute("type").as_string() == cur_type) {
                packet_series = ref_packet_node;
                break;
            }
        }

        if (packet_series.empty()) {
            // std::cout << "findParaInReference(): can't find PacketSeries\n" << std::endl;
            continue;
        }

        // find ref packet node that meets the id
        std::string cur_path;
        for (int j = i - 1; j >= 0; j--) {
            cur_path += type_path[j];
            if (j != 0) {
                cur_path += ".";
            }
        }
        for (pugi::xml_node ref_packet_node : packet_series.children("Packet")) {
            if (isPacketIdMeet(parent_node, ref_packet_node)) {
                // find the para node in ref_packet_node
                for (pugi::xml_node ref_para_node : ref_packet_node.children("Para")) {
                    if (ref_para_node.attribute("type").as_string() == cur_path) {
                        ref_node = ref_para_node;
                        return true;
                    }
                }
                // std::cout << "findParaInReference(): can't find Para meets type." << std::endl;
            }
        }
        // std::cout << "findParaInReference(): can't find Packet meets Id." << std::endl;
    }
    return false;
}

bool Mutator::isPacketIdMeet(pugi::xml_node packet_node, pugi::xml_node ref_packet_node) {
    for (pugi::xml_node ref_id_node : ref_packet_node.children("Id")) {
        std::string id_type = ref_id_node.attribute("type").as_string();
        // split id_type with "."
        std::vector<std::string> id_type_vec = splitString(id_type, '.');

        // find the node in packet_node
        pugi::xml_node id_node = packet_node;
        for (std::string id_type : id_type_vec) {
            for (pugi::xml_node node : id_node.children()) {
                if (node.attribute("type").as_string() == id_type) {
                    id_node = node;
                    break;
                }
            }
            if (id_node.attribute("type").as_string() != id_type) {
                // std::cerr << "isPacketIdMeet(): can't find id node in packet\n" << std::endl;
                return false;
            }
        }

        // check if the value of id node is the same
        std::vector<u8> cur_id_value;
        xml_extension.getNodeValue(id_node, cur_id_value);
        std::string cur_id_value_str(cur_id_value.begin(), cur_id_value.end());

        std::string ref_id_value = ref_id_node.child_value("Value");
        std::vector<u8> ref_id_value_vec = hexStringToBytes(ref_id_value);
        std::string ref_id_value_str(ref_id_value_vec.begin(), ref_id_value_vec.end());
        if (cur_id_value_str != ref_id_value_str) {
            return false;
        }
    }

    return true;
}

Mutator::RandomGenerator::RandomGenerator() :
    gen(rd()) {
    seed = rd();
    gen.seed(seed);
}

Mutator::RandomGenerator::RandomGenerator(unsigned int seed) {
    this->seed = seed;
    gen.seed(seed);
}

size_t Mutator::RandomGenerator::generateSizeT(size_t min, size_t max) {
    std::uniform_int_distribution<size_t> dis(min, max);
    return dis(gen);
}

int Mutator::RandomGenerator::generateRandomWithWeight(const std::vector<double> &weights) {
    if (weights.empty()) {
        std::cerr << "generateRandomWithWeight(): weights is empty\n";
        return -1;
    }
    std::discrete_distribution<int> distribution(weights.begin(), weights.end());
    return distribution(gen);
}

std::string Mutator::RandomGenerator::chooseRandomWithWeight(const std::vector<std::string> &choices, const std::vector<double> &weights) {
    if (choices.empty() || weights.empty()) {
        std::cerr << "chooseRandomWithWeight(): choices or weights is empty\n";
        return nullptr;
    }
    if (choices.size() != weights.size()) {
        std::cerr << "chooseRandomWithWeight(): choices and weights size not match\n";
        return nullptr;
    }
    std::discrete_distribution<int> distribution(weights.begin(), weights.end());
    return choices[distribution(gen)];
}

unsigned int Mutator::RandomGenerator::getSeed() const {
    return seed;
}

void Mutator::setDebugMode() {
    debug_mode = true;
}
