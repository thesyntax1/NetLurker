#pragma once
#include "json.h"
#include <map>
#include <cmath>
#include <cstdlib>
#include <climits>
#include <sstream>
#include <locale>

namespace nl { namespace strictjson {
struct Value {
    enum Kind { Null, Boolean, Number, String, Object, Array } kind = Null;
    bool flag = false;
    double number = 0;
    std::string text;
    std::map<std::string, Value> object;
    std::vector<Value> array;
    const Value& At(const std::string& key) const {
        static const Value missing;
        auto it = object.find(key);
        return kind == Object && it != object.end() ? it->second : missing;
    }
    bool Integer(int& out, int minimum = 0, int maximum = INT_MAX) const {
        if (kind != Number || !std::isfinite(number) || std::floor(number) != number || number < minimum || number > maximum) return false;
        out = static_cast<int>(number); return true;
    }
};
// Provider responses are untrusted. Reject partial documents, duplicate keys, invalid
// numeric tokens, excessive nesting and type coercions instead of inventing evidence.
class Parser {
    const std::string& s;
    size_t p = 0, nodes = 0;
    void Space() { while (p < s.size() && (s[p]==' ' || s[p]=='\t' || s[p]=='\n' || s[p]=='\r')) ++p; }
    bool Take(char c) { Space(); if (p == s.size() || s[p] != c) return false; ++p; return true; }
    bool Hex(unsigned& n) {
        n = 0;
        for (int i=0; i<4; ++i) {
            if (p == s.size()) return false;
            char c=s[p++]; int v=c>='0'&&c<='9'?c-'0':c>='a'&&c<='f'?c-'a'+10:c>='A'&&c<='F'?c-'A'+10:-1;
            if (v<0) return false;
            n=n*16+v;
        }
        return true;
    }
    bool Text(std::string& out) {
        if (!Take('"')) return false;
        size_t begin=p;
        while (p<s.size()) {
            unsigned char c=s[p++];
            if (c=='"') { out=json::Unescape(s.substr(begin,p-begin-1)); return true; }
            if (c<32) return false;
            if (c!='\\') continue;
            if (p==s.size()) return false;
            c=s[p++];
            if (c=='u') {
                unsigned cp; if (!Hex(cp)) return false;
                if (cp>=0xdc00 && cp<=0xdfff) return false;
                if (cp>=0xd800 && cp<=0xdbff) {
                    if (p+2>s.size() || s[p++]!='\\' || s[p++]!='u') return false;
                    if (!Hex(cp) || cp<0xdc00 || cp>0xdfff) return false;
                }
            } else if (std::string("\"\\/bfnrt").find(c)==std::string::npos) return false;
        }
        return false;
    }
    bool Read(Value& v, int depth) {
        Space();
        if (p==s.size() || depth>64 || ++nodes>100000) return false;
        char c=s[p];
        if (c=='{') {
            ++p; v.kind=Value::Object;
            if (Take('}')) return true;
            do {
                std::string key; Value child;
                if (!Text(key) || !Take(':') || !Read(child,depth+1) || !v.object.emplace(key,std::move(child)).second) return false;
                if (Take('}')) return true;
            } while (Take(','));
            return false;
        }
        if (c=='[') {
            ++p; v.kind=Value::Array;
            if (Take(']')) return true;
            do {
                Value child; if (!Read(child,depth+1)) return false;
                v.array.push_back(std::move(child));
                if (Take(']')) return true;
            } while (Take(','));
            return false;
        }
        if (c=='"') { v.kind=Value::String; return Text(v.text); }
        for (auto literal : {"true", "false", "null"}) {
            const std::string token=literal;
            if (s.compare(p,token.size(),token)==0) {
                p+=token.size(); v.kind=token=="null"?Value::Null:Value::Boolean; v.flag=token=="true"; return true;
            }
        }
        size_t start=p;
        if (s[p]=='-') ++p;
        if (p==s.size()) return false;
        if (s[p]=='0') ++p;
        else { if (s[p]<'1'||s[p]>'9') return false; while (p<s.size()&&s[p]>='0'&&s[p]<='9') ++p; }
        if (p<s.size()&&s[p]=='.') {
            size_t begin=++p; while(p<s.size()&&s[p]>='0'&&s[p]<='9') ++p; if (p==begin) return false;
        }
        if (p<s.size()&&(s[p]=='e'||s[p]=='E')) {
            ++p; if(p<s.size()&&(s[p]=='+'||s[p]=='-')) ++p;
            size_t begin=p; while(p<s.size()&&s[p]>='0'&&s[p]<='9') ++p; if(p==begin) return false;
        }
        // C-locale conversion is supplied explicitly; application locale cannot change scores.
        std::istringstream stream(s.substr(start,p-start)); stream.imbue(std::locale::classic());
        stream >> v.number;
        if (!stream || !std::isfinite(v.number)) return false;
        v.kind=Value::Number; return true;
    }
public:
    explicit Parser(const std::string& input):s(input){}
    bool Parse(Value& result) { Value v; if (!Read(v,0)) return false; Space(); if(p!=s.size()) return false; result=std::move(v); return true; }
};
inline bool Parse(const std::string& text, Value& out) { return text.size()<=2u*1024*1024 && Parser(text).Parse(out); }
} }
