#pragma once

#include <string>
#include <vector>

namespace nl {

void I18nSetLanguage(const std::wstring& code);

std::wstring I18nLanguage();

std::vector<std::pair<std::wstring, std::wstring>> I18nLanguages();

void I18nLoadFrom(const std::wstring& dir);

const wchar_t* Tr(const wchar_t* s);

std::wstring I18nSystemLanguage();

}
