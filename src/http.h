#pragma once
#include <string>

namespace nl { namespace http {

struct Response {
    bool ok = false;
    int  status = 0;
    std::string body;
    std::string error;
    std::wstring location;
};

Response Request(const std::string& method,
                 const std::string& url,
                 const std::string& body = "",
                 const std::string& contentType = "application/json",
                 const std::string& authBearer = "",
                 int timeoutMs = 15000,
                 const std::wstring& extraHeaders = L"");

}}
