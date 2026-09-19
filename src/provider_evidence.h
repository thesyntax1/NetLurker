#pragma once
#include "strict_json.h"
#include <set>

namespace nl { namespace provider {
using strictjson::Value;
struct Abuse {
    int abuseScore=-1, totalReports=0;
    bool isTor=false, isWhitelisted=false;
    std::string lastReport;
};
inline bool ReadAbuse(const std::string& body, const std::string& expectedIp, Abuse& out) {
    Value root;
    if (!strictjson::Parse(body,root)) return false;
    const auto& data=root.At("data");
    if (data.At("ipAddress").kind!=Value::String || data.At("ipAddress").text!=expectedIp) return false;
    Abuse next;
    if (!data.At("abuseConfidenceScore").Integer(next.abuseScore,0,100) || !data.At("totalReports").Integer(next.totalReports)) return false;
    for (auto key : {"isTor", "isWhitelisted"}) {
        const auto& v=data.At(key);
        if (v.kind!=Value::Null && v.kind!=Value::Boolean) return false;
    }
    next.isTor=data.At("isTor").flag;
    next.isWhitelisted=data.At("isWhitelisted").flag;
    next.lastReport=data.At("lastReportedAt").text;
    out=next; return true;
}
struct VirusTotal {
    int malicious=0, suspicious=0, total=0, reputation=0;
};
inline bool ReadVt(const std::string& body, const std::string& expectedIp, VirusTotal& out) {
    Value root;
    if (!strictjson::Parse(body,root)) return false;
    const auto& data=root.At("data");
    if (data.At("id").kind!=Value::String || data.At("id").text!=expectedIp || data.At("type").text!="ip_address") return false;
    const auto& attrs=data.At("attributes");
    const auto& stats=attrs.At("last_analysis_stats");
    VirusTotal next;
    int harmless=0, undetected=0;
    if (!stats.At("malicious").Integer(next.malicious) || !stats.At("suspicious").Integer(next.suspicious) ||
        !stats.At("harmless").Integer(harmless) || !stats.At("undetected").Integer(undetected)) return false;
    // Timeout/failure/type-unsupported are not verdicts and must not dilute this ratio.
    for (const auto& field : stats.object) { int count; if (!field.second.Integer(count)) return false; }
    long long total=static_cast<long long>(next.malicious)+next.suspicious+harmless+undetected;
    if (total<=0 || total>INT_MAX) return false;
    next.total=static_cast<int>(total);
    if (!attrs.At("reputation").Integer(next.reputation,INT_MIN)) return false;
    out=next; return true;
}
struct PassiveDns { int records=0; std::vector<std::string> names; };
inline bool ReadPdns(const std::string& body, const std::string& expectedIp, PassiveDns& out) {
    Value root; std::vector<Value> records;
    if (strictjson::Parse(body,root)) {
        if (root.kind==Value::Array) records=std::move(root.array);
        else if (root.kind==Value::Object) records.push_back(std::move(root));
        else return false;
    } else {
        // CIRCL also emits one JSON object per line. Validate every line, not just braces.
        std::istringstream lines(body); std::string line;
        while (std::getline(lines,line)) {
            if (line.find_first_not_of(" \t\r")==std::string::npos) continue;
            Value value;
            if (!strictjson::Parse(line,value) || value.kind!=Value::Object) return false;
            records.push_back(std::move(value));
        }
        if (records.empty()) return false;
    }
    PassiveDns next; std::set<std::string> names;
    for (const auto& row : records) {
        const auto& name=row.At("rrname");
        const auto& data=row.At("rdata");
        const auto& type=row.At("rrtype");
        if (name.kind!=Value::String || name.text.empty() || data.kind!=Value::String || data.text!=expectedIp ||
            (type.text!="A" && type.text!="AAAA")) return false;
        ++next.records;
        if (names.insert(name.text).second && next.names.size()<6) next.names.push_back(name.text);
    }
    out=next; return true;
}
} }
