#include "util/log/CLISink.h"

#include <Windows.h>

#include <iostream>

#include "util/Utils.h"

namespace Log {

    void CLISink::SetConsoleColor(CLISink::MessageColor color) {
        HANDLE hConsole = GetStdHandle(STD_OUTPUT_HANDLE);
        SetConsoleTextAttribute(hConsole, static_cast<WORD>(color));
    }

    CLISink::CLISink() : hMutex{ CreateMutexW(nullptr, false, L"Local\\CLI-Mutex") } {}

    void CLISink::LogMessage(IN CONST LogLevel& level, IN CONST std::wstring& message) {
        AcquireMutex mutex{ hMutex };
        if(level.Enabled()) {
            SetConsoleColor(CLISink::PrependColors[static_cast<WORD>(level.severity)]);
            std::wcout << CLISink::MessagePrepends[static_cast<WORD>(level.severity)] << " ";
            SetConsoleColor(CLISink::MessageColor::LIGHTGREY);
            std::wcout << message << std::endl;
        }
    }

    bool CLISink::operator==(IN CONST LogSink& sink) const { return (bool) dynamic_cast<const CLISink*>(&sink); }
}   // namespace Log
