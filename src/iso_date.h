#pragma once
#include <string>

namespace nl {
// Invalid/missing timestamps remain unknown (0); no rollover of impossible dates.
inline unsigned long long IsoEpoch(const std::string& s) {
    if (s.size()<20 || s[4]!='-' || s[7]!='-' || s[10]!='T' || s[13]!=':' || s[16]!=':') return 0;
    auto digits=[&](size_t p,int count) { int n=0; for(int i=0;i<count;++i) { if(p>=s.size()||s[p]<'0'||s[p]>'9') return -1; n=n*10+s[p++]-'0'; } return n; };
    int y=digits(0,4), m=digits(5,2), d=digits(8,2), hh=digits(11,2), mm=digits(14,2), ss=digits(17,2);
    if(y<1970||m<1||m>12||d<1||hh<0||hh>23||mm<0||mm>59||ss<0||ss>59) return 0;
    const int days[]={31,28,31,30,31,30,31,31,30,31,30,31};
    const bool leap=y%4==0&&(y%100!=0||y%400==0);
    if(d>days[m-1]+(m==2&&leap?1:0)) return 0;
    size_t p=19;
    if(s[p]=='.') { size_t begin=++p; while(p<s.size()&&s[p]>='0'&&s[p]<='9') ++p; if(p==begin) return 0; }
    if(p>=s.size()) return 0;
    int offset=0;
    if(s[p]=='Z') { if(++p!=s.size()) return 0; }
    else {
        if((s[p]!='+'&&s[p]!='-') || p+6!=s.size() || s[p+3]!=':') return 0;
        int oh=digits(p+1,2), om=digits(p+4,2);
        if(oh<0||oh>18||om<0||om>59||(oh==18&&om!=0)) return 0;
        offset=(oh*60+om)*60*(s[p]=='+'?1:-1);
    }
    y-=m<=2;
    const int era=y/400; const unsigned yoe=y-era*400;
    const unsigned doy=(153*(m+(m>2?-3:9))+2)/5+d-1;
    const unsigned doe=yoe*365+yoe/4-yoe/100+doy;
    const long long epoch=(era*146097LL+doe-719468LL)*86400+hh*3600+mm*60+ss-offset;
    return epoch>0?static_cast<unsigned long long>(epoch):0;
}
}
