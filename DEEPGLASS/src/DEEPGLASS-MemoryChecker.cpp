#include "DEEPGLASS/MemoryChecker.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <iostream>

#include "util/wrappers.hpp"
#include "util/StringUtils.h"
#include "util/DynamicLinker.h"

#include "DEEPGLASS/Filtering.h"
#include "DEEPGLASS/Internals.h"

LINK_FUNCTION(NtQuerySystemInformation, ntdll.dll);
LINK_FUNCTION(NtQueryObject, ntdll.dll);

namespace DEEPGLASS{

	HandleWrapper Internals::hEvent1{ CreateEventW(nullptr, false, false, nullptr) };
	HandleWrapper Internals::hEvent2{ CreateEventW(nullptr, false, false, nullptr) };
	Internals::ThreadInfo* Internals::info{ nullptr };
	HANDLE Internals::hThread{ nullptr };

	void ScanLoadedModules(_Out_ std::unordered_map<std::wstring, std::vector<DWORD>>& found){
        std::cout << "Scanning modules loaded into processes!" << std::endl;

        HandleWrapper hModuleSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, 0);
        if(!hModuleSnapshot){
            std::cerr << "Unable to enumerate modules" << std::endl;
        }

        MODULEENTRY32W mod = { sizeof(MODULEENTRY32W), 0 };
        if(!Module32FirstW(hModuleSnapshot, &mod)){
            std::cerr << "Unable to the first module" << std::endl;
        }

        do {
            auto path{ ToLowerCaseW(mod.szExePath) };
            if(IsPEFile(path) && !FileSystem::File{ path }.GetFileSigned()){
                if(found.find(path) == found.end()){
                    found.emplace(path, std::vector<DWORD>{});
                }
                found.at(path).emplace_back(mod.th32ProcessID);
            }
        } while(Module32NextW(hModuleSnapshot, &mod));
	}

	void QueryName(){
		while(true){
			WaitForSingleObject(Internals::hEvent1, INFINITE);
			DWORD dwLength{ 0 };
			NTSTATUS status{ static_cast<NTSTATUS>(0xC0000000L) };
			while(0xC0000004L == (status = Linker::NtQueryObject(
				Internals::info->handle, ObjectNameInformation, Internals::info->buf.data(), 
				Internals::info->buf.size(), &dwLength))){
				
				Internals::info->buf.resize(dwLength + 0x100);
			}
			if(!NT_SUCCESS(status)){
				Internals::info->buf = {};
			}
			SetEvent(Internals::hEvent2);
		}
	}

	std::optional<std::wstring> GetHandleName(HANDLE handle, DWORD dwPID){
		HandleWrapper hProcess{ OpenProcess(PROCESS_DUP_HANDLE, false, dwPID) };
		if(hProcess){
			Internals::ThreadInfo localinfo{};
			DuplicateHandle(hProcess, handle, GetCurrentProcess(), &localinfo.handle,
							0, FALSE, DUPLICATE_SAME_ACCESS);
			CloseHandle(hProcess.Release());

			if(!Internals::hThread){
				Internals::hThread = CreateThread(nullptr, 0, LPTHREAD_START_ROUTINE(QueryName), nullptr, 0, nullptr);
			}

			Internals::info = &localinfo;
			SetEvent(Internals::hEvent1);
			if(WAIT_OBJECT_0 == WaitForSingleObject(Internals::hEvent2, 250)){
				CloseHandle(localinfo.handle);
				auto str{ reinterpret_cast<PUNICODE_STRING>(localinfo.buf.data()) };
				if(!localinfo.buf.size() || !str->Buffer){
					CloseHandle(hProcess.Release());
					return std::nullopt;
				}
				return std::wstring{ str->Buffer };
			} else{
				TerminateThread(Internals::hThread, 0);
				Internals::hThread = nullptr;
			}
		}
		return std::nullopt;
	}

    void EnumerateHandles(){
		DWORD dwLength{};
		std::vector<char> buf{};
		NTSTATUS status{};
		while(0xC0000004L ==
			  (status = Linker::NtQuerySystemInformation(SystemHandleInformation, buf.data(), buf.size(), &dwLength))){
			buf.resize(dwLength + 0x1000);
		}
		if(!NT_SUCCESS(status)){
			std::cerr << "Failed to retrieve information on handles!" << std::endl;
			return;
		}



		auto info{ reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buf.data()) };
		for(auto i = 0u; i < info->HandleCount; i++){
			auto path{ GetHandleName(reinterpret_cast<HANDLE>(info->Handles[i].HandleValue),
									 info->Handles[i].UniqueProcessId) };
			if(path){
				std::wcout << *path << std::endl;
			}
		}
    }

    void ScanHandleTables(_Out_ std::unordered_map<std::wstring, std::vector<DWORD>>& found,
                          _In_opt_ const std::unordered_set<std::wstring>& files){
		EnumerateHandles();
    }
};