#pragma once

#include <Windows.h>

#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace DEEPGLASS {

	void ScanLoadedModules(_Out_ std::unordered_map<std::wstring, std::vector<DWORD>>& found);
	void ScanHandleTables(_Out_ std::unordered_map<std::wstring, std::vector<DWORD>>& found, 
						  _In_opt_ const std::unordered_set<std::wstring>& files = {});
	void RunMemoryChecks(_Inout_ std::unordered_set<std::wstring>& files);
}