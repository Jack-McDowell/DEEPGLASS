#pragma once

#include <Windows.h>

#include <unordered_set>

namespace DEEPGLASS {
	void RunFileChecks(_Out_ std::unordered_set<std::wstring>& paths);
}