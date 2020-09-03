#include <Windows.h>

#include <sstream>

#include "util/log/DebugSink.h"
#include "util/Utils.h"

#define DEBUG_STREAM(...) \
    OutputDebugStringW((std::wstringstream{} << __VA_ARGS__).str().c_str())

#define DETECTION_DEBUG_STREAM(...)                                                                                  \
    DEBUG_STREAM((type == RecordType::PreScan ? L"[Pre-Scan Detection]" : L"[Detection]") << L"[ID " << detection->dwID << \
                 L"]" << __VA_ARGS__);

namespace Log{

	void DebugSink::LogMessage(IN CONST LogLevel& level, IN CONST std::wstring& message){
		BeginCriticalSection _{ hGuard };

		if(level.Enabled()){
			DEBUG_STREAM(DebugSink::MessagePrepends[static_cast<WORD>(level.severity)] << L" " << message);
		}
	}

	bool DebugSink::operator==(IN CONST LogSink& sink) const{
		return (bool) dynamic_cast<const DebugSink*>(&sink);
	}
}
