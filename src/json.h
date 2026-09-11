#pragma once
#include <string>
#include <vector>

namespace nl { namespace json {

std::string Unescape(const std::string& s);

std::string Escape(const std::string& s);

bool GetString(const std::string& obj, const std::string& name, std::string& out);

bool GetNumber(const std::string& obj, const std::string& name, double& out);

std::vector<std::string> SplitObjects(const std::string& arrayText);

bool FindStringDeep(const std::string& text, const std::string& name, std::string& out);

}}
