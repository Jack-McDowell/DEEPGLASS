#pragma once

#include <Windows.h>

#include <vector>
#include <string>

#include "util/wrappers.hpp"
#include "util/dynamiclinker.h"

struct Hook {
	LPVOID ModificationAddress;
	LPVOID RedirectionAddress;
};

DEFINE_FUNCTION(NTSTATUS, NtQueryInformationProcess, __kernel_entry NTAPI, IN HANDLE ProcessHandle,
				IN PROCESSINFOCLASS ProcessInformationClass, OUT PVOID ProcessInformation, IN ULONG ProcessInnformationLength,
				OUT PULONG ReturnLength);

bool HookIsOkay(const Hook& hook);

std::vector<LPVOID> GetExecutableNonImageSections(DWORD pid);
std::vector<LPVOID> GetUnregisteredImages(DWORD pid);
std::vector<LPVOID> GetModifiedImages(DWORD pid);
std::vector<LPVOID> GetHooks(DWORD pid);

std::wstring GetProcessImage(DWORD dwPID);
std::wstring GetProcessImage(const HandleWrapper& hProcess);
std::wstring GetProcessCommandline(DWORD dwPID);
std::wstring GetProcessCommandline(const HandleWrapper& hProcess);
std::wstring GetImagePathFromCommand(std::wstring wsCmd);
std::vector<std::wstring> EnumModules(DWORD dwPID);
std::vector<std::wstring> EnumModules(const HandleWrapper& hProcess);
LPVOID GetModuleAddress(DWORD dwPID, const std::wstring& wsModuleName);
LPVOID GetModuleAddress(const HandleWrapper& hProcess, const std::wstring& wsModuleName);
DWORD GetRegionSize(DWORD dwPID, LPVOID lpRegionAddress);
DWORD GetRegionSize(const HandleWrapper& hProcess, LPVOID lpRegionAddress);

namespace Utils::Process {
	AllocationWrapper ReadProcessMemory(const HandleWrapper& hProcess, LPVOID lpBaseAddress, DWORD dwSize);
	AllocationWrapper ReadProcessMemory(DWORD dwPID, LPVOID lpBaseAddress, DWORD dwSize);
}
