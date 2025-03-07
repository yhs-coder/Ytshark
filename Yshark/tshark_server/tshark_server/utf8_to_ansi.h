#ifndef UTF8_TO_ANSI_H
#define UTF8_TO_ANSI_H
#include <string>

#ifdef _WIN32
#include <windows.h>
// UTF-8转ANSI
static std::string UTF8TOANSIString(const std::string& utf8Str) {
	// 获取UTF-8字符串的长度
	int utf8Length = static_cast<int>(utf8Str.length());

	// 将UTF-8转换为宽字符（UTF-16）
	int wideLength = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, nullptr, 0);
	std::wstring wideStr(wideLength, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, &wideStr[0], wideLength);

	// 将宽字符（UTF-16）转换为ANSI
	int ansiLength = WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, nullptr, 0, nullptr, nullptr);
	std::string ansiStr(ansiLength, '\0');
	WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, &ansiStr[0], ansiLength, nullptr, nullptr);
	return ansiStr;
}

#endif

#endif