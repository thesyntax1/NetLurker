#include "json.h"
#include <cstdlib>
#include <cstdio>

namespace nl { namespace json {

static bool ReadStringAt(const std::string& s, size_t quotePos, std::string& raw, size_t& endPos) {
    if (quotePos >= s.size() || s[quotePos] != '"') return false;
    size_t i = quotePos + 1;
    std::string out;
    while (i < s.size()) {
        char ch = s[i];
        if (ch == '\\') {
            if (i + 1 >= s.size()) return false;
            out.push_back(ch);
            out.push_back(s[i + 1]);
            i += 2;
            continue;
        }
        if (ch == '"') { raw = out; endPos = i + 1; return true; }
        out.push_back(ch);
        ++i;
    }
    return false;
}

std::string Unescape(const std::string& s) {
    std::string out;
    out.reserve(s.size());
    for (size_t i = 0; i < s.size(); ++i) {
        if (s[i] != '\\') { out.push_back(s[i]); continue; }
        if (i + 1 >= s.size()) break;
        char c = s[++i];
        switch (c) {
            case 'n': out.push_back('\n'); break;
            case 't': out.push_back('\t'); break;
            case 'r': out.push_back('\r'); break;
            case 'b': out.push_back('\b'); break;
            case 'f': out.push_back('\f'); break;
            case '"': out.push_back('"');  break;
            case '\\':out.push_back('\\'); break;
            case '/': out.push_back('/');  break;
            case 'u': {
                if (i + 4 < s.size()) {
                    std::string hex = s.substr(i + 1, 4);
                    unsigned cp = (unsigned)strtoul(hex.c_str(), nullptr, 16);
                    i += 4;

                    if (cp < 0x80) out.push_back((char)cp);
                    else if (cp < 0x800) {
                        out.push_back((char)(0xC0 | (cp >> 6)));
                        out.push_back((char)(0x80 | (cp & 0x3F)));
                    } else if (cp >= 0xD800 && cp <= 0xDBFF && i + 6 < s.size() &&
                               s[i + 1] == '\\' && s[i + 2] == 'u') {
                        unsigned lo = (unsigned)strtoul(s.substr(i + 3, 4).c_str(), nullptr, 16);
                        i += 6;
                        unsigned full = 0x10000 + ((cp - 0xD800) << 10) + (lo - 0xDC00);
                        out.push_back((char)(0xF0 | (full >> 18)));
                        out.push_back((char)(0x80 | ((full >> 12) & 0x3F)));
                        out.push_back((char)(0x80 | ((full >> 6) & 0x3F)));
                        out.push_back((char)(0x80 | (full & 0x3F)));
                    } else {
                        out.push_back((char)(0xE0 | (cp >> 12)));
                        out.push_back((char)(0x80 | ((cp >> 6) & 0x3F)));
                        out.push_back((char)(0x80 | (cp & 0x3F)));
                    }
                }
                break;
            }
            default: out.push_back(c); break;
        }
    }
    return out;
}

std::string Escape(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 16);
    for (unsigned char c : s) {
        switch (c) {
            case '"':  out += "\\\""; break;
            case '\\': out += "\\\\"; break;
            case '\n': out += "\\n";  break;
            case '\r': out += "\\r";  break;
            case '\t': out += "\\t";  break;
            default:
                if (c < 0x20) { char b[8]; snprintf(b, 8, "\\u%04x", c); out += b; }
                else out.push_back((char)c);
        }
    }
    return out;
}

static bool FindKey(const std::string& s, const std::string& name, size_t from, size_t& valuePos) {
    const std::string pat = "\"" + name + "\"";
    size_t i = from;
    while (i < s.size()) {
        if (s[i] == '"') {
            std::string raw; size_t end;
            if (!ReadStringAt(s, i, raw, end)) return false;
            if (raw == name) {
                size_t j = end;
                while (j < s.size() && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r')) ++j;
                if (j < s.size() && s[j] == ':') {
                    ++j;
                    while (j < s.size() && (s[j] == ' ' || s[j] == '\t' || s[j] == '\n' || s[j] == '\r')) ++j;
                    valuePos = j;
                    return true;
                }
            }
            i = end;
            continue;
        }
        ++i;
    }
    (void)pat;
    return false;
}

bool GetString(const std::string& obj, const std::string& name, std::string& out) {
    size_t vp;
    if (!FindKey(obj, name, 0, vp)) return false;
    if (vp >= obj.size() || obj[vp] != '"') return false;
    std::string raw; size_t end;
    if (!ReadStringAt(obj, vp, raw, end)) return false;
    out = Unescape(raw);
    return true;
}

bool GetBool(const std::string& obj, const std::string& name, bool& out) {
    size_t vp;
    if (!FindKey(obj, name, 0, vp)) return false;
    if (obj.compare(vp, 4, "true") == 0) { out = true; return true; }
    if (obj.compare(vp, 5, "false") == 0) { out = false; return true; }
    return false;
}

bool GetNumber(const std::string& obj, const std::string& name, double& out) {
    size_t vp;
    if (!FindKey(obj, name, 0, vp)) return false;
    char* endp = nullptr;
    double v = strtod(obj.c_str() + vp, &endp);
    if (endp == obj.c_str() + vp) return false;
    out = v;
    return true;
}

bool FindStringDeep(const std::string& text, const std::string& name, std::string& out) {
    size_t from = 0;
    while (from < text.size()) {
        size_t vp;
        if (!FindKey(text, name, from, vp)) return false;
        if (vp < text.size() && text[vp] == '"') {
            std::string raw; size_t end;
            if (ReadStringAt(text, vp, raw, end)) { out = Unescape(raw); return true; }
        }
        from = vp + 1;
    }
    return false;
}

std::vector<std::string> SplitObjects(const std::string& arr) {
    std::vector<std::string> objs;
    int depth = 0;
    size_t start = 0;
    for (size_t i = 0; i < arr.size(); ++i) {
        char c = arr[i];
        if (c == '"') {
            std::string raw; size_t end;
            if (ReadStringAt(arr, i, raw, end)) { i = end - 1; continue; }
            break;
        }
        if (c == '{') { if (depth == 0) start = i; ++depth; }
        else if (c == '}') {
            --depth;
            if (depth == 0) objs.push_back(arr.substr(start, i - start + 1));
            if (depth < 0) depth = 0;
        }
    }
    return objs;
}

}}
