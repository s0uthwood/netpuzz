#ifndef INCLUDE_XML_EXTENSION_HPP_
#define INCLUDE_XML_EXTENSION_HPP_

#include <string>
#include <vector>

#include "./defines.hpp"
#include "pugixml/pugixml.hpp"

class XmlExtension {
 public:
    pugi::xml_document loadXmlWithEntities(const std::string &fileName);

    void getNodeValue(pugi::xml_node data_node, std::vector<u8> &buffer);
    void assembleNodes(pugi::xml_node node, std::vector<u8> &buffer);

    void getChildNodes(pugi::xml_node node, std::vector<pugi::xml_node> &child_nodes);
    void getAllNodes(pugi::xml_node node, std::vector<pugi::xml_node> &pre_order);
    void getAllLeafNodes(pugi::xml_node node, std::vector<pugi::xml_node> &leaf_nodes);
    void getAllNodesByName(pugi::xml_node node, std::string name, std::vector<pugi::xml_node> *nodes);
    void getAllNodesByNameInPostOrder(pugi::xml_node node, std::string name, std::vector<pugi::xml_node> &nodes);

    void printNode(pugi::xml_node node);

 private:
    std::string readFileToString(const std::string &fileName);
    std::string replaceEntities(const std::string &xml_string);
};

#endif  // INCLUDE_XML_EXTENSION_HPP_
