#pragma once
#include <string>

#ifdef _WIN32
#include <windows.h>
// UTF-8תANSI
static std::string UTF8TOANSIString(const std::string& utf8Str) {
	// ��ȡUTF-8�ַ����ĳ���
	int utf8Length = static_cast<int>(utf8Str.length());

	// ��UTF-8ת��Ϊ���ַ���UTF-16��
	int wideLength = MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, nullptr, 0);
	std::wstring wideStr(wideLength, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, utf8Str.c_str(), utf8Length, &wideStr[0], wideLength);

	// �����ַ���UTF-16��ת��ΪANSI
	int ansiLength = WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, nullptr, 0, nullptr, nullptr);
	std::string ansiStr(ansiLength, '\0');
	WideCharToMultiByte(CP_ACP, 0, wideStr.c_str(), wideLength, &ansiStr[0], ansiLength, nullptr, nullptr);
	return ansiStr;
}

#endif
