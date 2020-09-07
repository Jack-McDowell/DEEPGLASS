#include "DEEPGLASS/MemoryChecker.h"

#include <Windows.h>
#include <Psapi.h>
#include <TlHelp32.h>

#include <iostream>
#include <fstream>

#include "util/wrappers.hpp"
#include "util/StringUtils.h"
#include "util/Threadpool.h"
#include "util/DynamicLinker.h"
#include "util/processes/ProcessUtils.h"

#include "DEEPGLASS/Filtering.h"
#include "DEEPGLASS/Internals.h"

LINK_FUNCTION(NtQuerySystemInformation, ntdll.dll);
LINK_FUNCTION(NtQueryObject, ntdll.dll);

namespace DEEPGLASS{

	HandleWrapper Internals::hEvent1{ CreateEventW(nullptr, false, false, nullptr) };
	HandleWrapper Internals::hEvent2{ CreateEventW(nullptr, false, false, nullptr) };
	Internals::ThreadInfo* Internals::info{ nullptr };
	HANDLE Internals::hThread{ nullptr };

	void ScanLoadedModules(_Out_ std::unordered_map<std::wstring, std::unordered_set<DWORD>>& found){
        std::cout << "Scanning modules loaded into processes!" << std::endl;

		std::vector<DWORD> processes(1024);
		DWORD dwBytesNeeded{};
		auto success{ EnumProcesses(processes.data(), 1024 * sizeof(DWORD), &dwBytesNeeded) };
		if(dwBytesNeeded > 1024 * sizeof(DWORD)){
			processes.resize(dwBytesNeeded / sizeof(DWORD));
			success = EnumProcesses(processes.data(), dwBytesNeeded, &dwBytesNeeded);
		}

		std::vector<Promise<bool>> promises{};
		CriticalSection hGuard{};
		auto dwProcCount{ dwBytesNeeded / sizeof(DWORD) };
		for(int i = 0; i < dwProcCount; i++){
			auto proc{ processes[i] };
			promises.emplace_back(ThreadPool::GetInstance().RequestPromise<bool>([&hGuard, proc, &found](){
				auto modules{ EnumModules(proc) };
				for(auto& mod : modules){
					auto name{ ToLowerCaseW(mod) };
					if(found.find(name) == found.end()){
						found.emplace(name, std::unordered_set<DWORD>{ proc });
					} else{
						found.at(name).emplace(proc);
					}
				}
				return true;
			}));
		}

		for(const auto& promise : promises){
			promise.GetValue();
		}
	}

	void Internals::QueryName(){
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

	std::optional<std::wstring> Internals::GetHandleName(_In_ HANDLE handle, _In_ DWORD dwPID){
		HandleWrapper hProcess{ OpenProcess(PROCESS_DUP_HANDLE, false, dwPID) };
		if(hProcess){
			Internals::ThreadInfo localinfo{};
			DuplicateHandle(hProcess, handle, GetCurrentProcess(), &localinfo.handle,
							0, FALSE, DUPLICATE_SAME_ACCESS);
			CloseHandle(hProcess.Release());

			if(!Internals::hThread){
				Internals::hThread = CreateThread(nullptr, 0, LPTHREAD_START_ROUTINE(Internals::QueryName), nullptr, 
												  0, nullptr);
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

    void EnumerateHandles(_Out_ std::unordered_map<std::wstring, std::unordered_set<DWORD>>& found){
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
		
		std::vector<WCHAR> drives(512);
		std::map<std::wstring, std::wstring> translation{};
		if(GetLogicalDriveStringsW(512, drives.data())){
			WCHAR* driveletter{ drives.data() };
			WCHAR path[3]{ L"?:" };
			while(*driveletter){
				*path = *driveletter;
				std::vector<WCHAR> prefix(MAX_PATH);
				if(QueryDosDeviceW(path, prefix.data(), MAX_PATH)){
					translation.emplace(prefix.data(), path);
				}
				while(*++driveletter);
				driveletter++;
			}
		} else{
			std::cerr << "Failed to translate kernel paths to DOS paths" << std::endl;
		}

		auto info{ reinterpret_cast<SYSTEM_HANDLE_INFORMATION*>(buf.data()) };
		for(auto i = 0u; i < info->HandleCount; i++){
			auto path{ Internals::GetHandleName(reinterpret_cast<HANDLE>(info->Handles[i].HandleValue),
									            info->Handles[i].UniqueProcessId) };
			if(path){
				for(const auto& pair : translation){
					if(path->substr(0, pair.first.size()) == pair.first){
						auto dospath{ ToLowerCaseW(pair.second + path->substr(pair.first.size())) };
						if(found.find(dospath) == found.end()){
							found.emplace(dospath, std::unordered_set<DWORD>{});
						}
						found.at(dospath).emplace(info->Handles[i].UniqueProcessId);
					}
				}
			}
		}
    }

	void ScanFilesWithPIDs(_In_ const std::unordered_map<std::wstring, std::unordered_set<DWORD>>& files,
						   _Out_ std::unordered_set<std::wstring>& paths, _In_ const std::wstring& path){
		std::vector<Promise<bool>> promises{};
		std::wofstream unsignedfile(path);
		CriticalSection hGuard{};
		for(const auto& file : files){
			promises.emplace_back(
				ThreadPool::GetInstance().RequestPromise<bool>([file, &hGuard, &unsignedfile, &paths](){
					if(DEEPGLASS::IsFiletypePE(file.first) && !FileSystem::File{ file.first }.GetFileSigned()){
						EnterCriticalSection(hGuard);
						paths.emplace(file.first);
						unsignedfile << L"File " << file.first << L" is unsigned. Open in these processes: "
							<< std::endl;
						for(const auto& pid : file.second){
							unsignedfile << L"\tProcess with PID " << pid << L" (Name: " << GetProcessImage(pid)
								<< L")" << std::endl;
						}
						LeaveCriticalSection(hGuard);
					}
					return true;
				})
			);
		}
		for(const auto& promise : promises){
			promise.GetValue();
		}
	}

    void ScanHandleTables(_Inout_ std::unordered_set<std::wstring>& files){
		std::cout << "Scanning handles" << std::endl;

		std::unordered_map<std::wstring, std::unordered_set<DWORD>> found{};
		EnumerateHandles(found);

		std::wofstream openhandle(L".\\DEEPGLASS-Results\\Identified-Open-In-Handles.txt");
		for(const auto& file : files){
			if(found.find(file) != found.end()){
				const auto& pids{ found.at(file) };
				openhandle << L"Previously identified file " << file << " found as an open handle in these processes: " 
					<< std::endl;
				for(const auto& pid : pids){
					openhandle << L"\tProcess with PID " << pid << L" (Name: " << GetProcessImage(pid) << L")" 
						<< std::endl;
				}
			}
		}

		ScanFilesWithPIDs(found, files, L".\\DEEPGLASS-Results\\Unsigned-PE-Handles.txt");
    }

	void RunMemoryChecks(_Inout_ std::unordered_set<std::wstring>& files){

		std::unordered_map<std::wstring, std::unordered_set<DWORD>> found{};
		ScanLoadedModules(found);
		ScanFilesWithPIDs(found, files, L".\\DEEPGLASS-Results\\Unsigned-Loaded-Modules.txt");

		ScanHandleTables(files);
	}
};