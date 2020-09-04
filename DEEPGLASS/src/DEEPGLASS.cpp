#include "DEEPGLASS/EnumRegistry.h"
#include "DEEPGLASS/Filtering.h"
#include "DEEPGLASS/FileCollector.h"

#include "util/ThreadPool.h"
#include "util/StringUtils.h"

#include <iostream>
#include <fstream>

void RunRegistryChecks(_Out_ std::unordered_set<std::wstring>& paths){
	std::unordered_map<std::wstring, std::vector<Registry::RegistryValue>> found{};
	std::unordered_set<std::wstring> explored;
	CriticalSection hFoundGuard{}, hExploredGuard{};
	DEEPGLASS::EnumerateValuesRecursive(HKEY_LOCAL_MACHINE, found, explored, hFoundGuard, hExploredGuard, true);
	DEEPGLASS::EnumerateValuesRecursive(HKEY_USERS, found, explored, hFoundGuard, hExploredGuard, true);
	ThreadPool::GetInstance().Wait();

	std::vector<std::pair<std::wstring, std::vector<Registry::RegistryValue>>> notsigned{};
	std::vector<std::pair<std::wstring, std::vector<Registry::RegistryValue>>> notfound{};
	DEEPGLASS::FilterSigned(found, notsigned, notfound);

	std::wofstream missingfile(L".\\DEEPGLASS-Results\\Registry-Missing-Files.txt");
	for(const auto& pair : notfound){
		missingfile << L"File " << pair.first << L" not found; referenced by:" << std::endl;
		for(const auto& value : pair.second){
			missingfile << "\t" << value.key.GetName() << L": " << value.GetPrintableName() << std::endl;
		}
	}

	std::wofstream unsignedfile(L".\\DEEPGLASS-Results\\Registry-Unsigned-Files.txt");
	for(const auto& pair : notsigned){
		unsignedfile << L"File " << pair.first << L" is unsigned; referenced by:" << std::endl;
		for(const auto& value : pair.second){
			unsignedfile << "\t" << value.key.GetName() << L": " << value.GetPrintableName() << std::endl;
		}
		paths.emplace(pair.first);
	}
}

void RunFileChecks(_Out_ std::unordered_set<std::wstring>& paths){
	auto length{ GetEnvironmentVariableW(L"PATH", nullptr, 0) };
	std::unordered_set<std::wstring> locations{ L"C:\\", L"%SystemRoot%", L"%SystemRoot%\\System",
		L"%SystemRoot%\\System32", L"%SystemRoot%\\System32\\Wbem", L"%SystemRoot%\\System32\\WindowsPowerShell\\v1.0",
		L"%SystemRoot%\\SysWOW64", L"%SystemRoot%\\SysWOW64\\Wbem", L"%SystemRoot%\\SysWOW64\\WindowsPowerShell\\v1.0" };
	if(length){
		std::vector<WCHAR> buf(length);
		if(length >= GetEnvironmentVariableW(L"PATH", buf.data(), length)){
			auto pathlocs{ SplitStringW(buf.data(), L";") };
			for(const auto& loc : pathlocs){
				locations.emplace(loc);
				auto lower{ ToLowerCaseW(loc) };
				if(lower.find(L"system32") != std::wstring::npos){
					locations.emplace(StringReplaceW(lower, L"system32", L"syswow64"));
				}
			}
		} else{
			std::cerr << "Unable to read %PATH%; defaulting to the default system directories" << std::endl;
		}
	}

	std::wofstream unsignedfile(L".\\DEEPGLASS-Results\\Path-Unsigned-Files.txt");
	for(const auto& directory : locations){
		FileSystem::Folder folder{ ExpandEnvStringsW(directory) };
		auto files{ folder.GetFiles() };
		for(const auto& file : files){
			if(DEEPGLASS::IsFiletypePE(file.GetFilePath()) && !file.GetFileSigned()){
				paths.emplace(file);
				unsignedfile << L"File " << file.GetFilePath() << L" is unsigned" << std::endl;
			}
		}
	}
}

void main(){
	if(!DEEPGLASS::InitializeDirectory()){
		std::cerr << "Failed to initialize directory for outputs; aborting!" << std::endl;
	} else {
		std::unordered_set<std::wstring> files{};

		RunRegistryChecks(files);
		RunFileChecks(files);

		DEEPGLASS::MoveFiles(files);
	}
}