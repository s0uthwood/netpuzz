#include "./xml_extension.hpp"

#include <fstream>
#include <iostream>
#include <regex>
#include <sstream>
#include <string>
#include <unordered_map>

// append data_node's "value" attribute to buffer
void XmlExtension::getNodeValue(pugi::xml_node data_node, std::vector<u8> &buffer) {
    std::string data = data_node.attribute("value").value();
    std::istringstream iss(data);
    std::string byte;
    while (iss >> byte) {
        buffer.push_back(static_cast<u8>(std::stoi(byte, nullptr, 16)));
    }
}

// NOTE: Only assemble the value in xml file.
//       Size information should be maintained by mutator.
//       Remenber, the size should be updated everytime a mutation is applied.
void XmlExtension::assembleNodes(pugi::xml_node node, std::vector<u8> &buffer) {
    // Debug print buffer
    std::string name = node.name();
    if (name == "Size" || name == "Data") {
        getNodeValue(node, buffer);
    } else if (name == "Block" || name == "Packet") {
        for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
            assembleNodes(child, buffer);
        }
    } else if (name == "Sequence") {
        std::cout << "Error: Sequence node should not be here." << std::endl;
    } else {
        std::cout << "Error: Unknown node name: " << name << std::endl;
    }
}

void XmlExtension::getChildNodes(pugi::xml_node node, std::vector<pugi::xml_node> &child_nodes) {
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        child_nodes.push_back(child);
    }
}

void XmlExtension::getAllNodes(pugi::xml_node node, std::vector<pugi::xml_node> &pre_order) {
    pre_order.push_back(node);
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        getAllNodes(child, pre_order);
    }
}

// NOTE: Leaf nodes are Data, Size, Checksum
void XmlExtension::getAllLeafNodes(pugi::xml_node node, std::vector<pugi::xml_node> &leaf_nodes) {
    std::string name = node.name();
    if (name == "Data" || name == "Size" || name == "Checksum") {
        leaf_nodes.push_back(node);
    } else if (name == "Block" || name == "Packet" || name == "Sequence") {
        for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
            getAllLeafNodes(child, leaf_nodes);
        }
    } else {
        std::cout << "Error: Unknown node name: " << name << std::endl;
    }
}

void XmlExtension::getAllNodesByName(pugi::xml_node node, std::string name, std::vector<pugi::xml_node> *nodes) {
    if (!node) {
        std::cout << "Error: node is null." << std::endl;
        return;
    }
    if (node.name() == name) {
        nodes->push_back(node);
    }
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        getAllNodesByName(child, name, nodes);
    }
}

void XmlExtension::getAllNodesByNameInPostOrder(pugi::xml_node node, std::string name, std::vector<pugi::xml_node> &nodes) {
    if (!node) {
        std::cout << "Error: node is null." << std::endl;
        return;
    }
    for (pugi::xml_node child = node.first_child(); child; child = child.next_sibling()) {
        getAllNodesByNameInPostOrder(child, name, nodes);
    }
    if (node.name() == name) {
        nodes.push_back(node);
    }
}

pugi::xml_document XmlExtension::loadXmlWithEntities(const std::string &fileName) {
    std::string xml_string = readFileToString(fileName);
    std::string replaced_xml_str = replaceEntities(xml_string);
    pugi::xml_document doc;
    pugi::xml_parse_result result = doc.load_string(replaced_xml_str.c_str());
    if (!result) {
        throw std::runtime_error("Could not parse XML: " + std::string(result.description()));
    }
    return doc;
}

void XmlExtension::printNode(pugi::xml_node node) {
    std::ostringstream oss;
    node.print(oss);
    std::cout << oss.str() << std::endl;
}

std::string XmlExtension::readFileToString(const std::string &fileName) {
    std::ifstream ifs(fileName);
    if (!ifs.is_open()) {
        throw std::runtime_error("Could not open file: " + fileName);
    }
    std::stringstream buffer;
    buffer << ifs.rdbuf();
    return buffer.str();
}

std::string XmlExtension::replaceEntities(const std::string &xml_string) {
    std::string content = xml_string;
    std::regex entity_regex("<!ENTITY\\s+(\\S+)\\s+\"(.+?)\">");
    std::smatch match;
    std::unordered_map<std::string, std::string> entity_map;

    // create map: entity_name -> entity_value
    while (std::regex_search(content, match, entity_regex)) {
        // perfect match
        if (match.size() == 3) {
            std::string entity_name = match[1].str();
            std::string entity_value = match[2].str();
            entity_map["&" + entity_name + ";"] = entity_value;
        }
        content = match.suffix();
    }

    // replace string
    for (const auto &entity : entity_map) {
        size_t start_pos = 0;
        while ((start_pos = content.find(entity.first, start_pos)) != std::string::npos) {
            content.replace(start_pos, entity.first.length(), entity.second);
            start_pos += entity.second.length();
        }
    }

    return content;
}
