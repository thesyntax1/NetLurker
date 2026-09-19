#pragma once
#include <string>

namespace nl { namespace http {

// The free geolocation batch API is an explicitly disclosed plaintext service.
// No other caller may opt arbitrary endpoints/credentials out of transport protection.
enum class RequestPolicy { Protected, PublicGeolocation };

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
                 const std::wstring& extraHeaders = L"",
                 RequestPolicy policy = RequestPolicy::Protected);

}}
