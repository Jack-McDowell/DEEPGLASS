#include "DEEPGLASS/EnumRegistry.h"
#include "DEEPGLASS/Filtering.h"

#include <shlwapi.h>

#include <unordered_map>
#include <string>
#include <fstream>

#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"
#include "util/log/Log.h"
#include "util/ThreadPool.h"

#include <iostream>

namespace DEEPGLASS {

	void RunRegistryChecks(_Out_ std::unordered_set<std::wstring>& paths){
		std::cout << "Beginning the registry scan" << std::endl;

		std::unordered_map<std::wstring, std::vector<Registry::RegistryValue>> found{};
		std::unordered_set<std::wstring> explored;
		CriticalSection hFoundGuard{}, hExploredGuard{};
		DEEPGLASS::EnumerateValuesRecursive(HKEY_LOCAL_MACHINE, found, explored, hFoundGuard, hExploredGuard, true);
		DEEPGLASS::EnumerateValuesRecursive(HKEY_USERS, found, explored, hFoundGuard, hExploredGuard, true);
		ThreadPool::GetInstance().Wait();

		std::cout << "Gathered all path-like strings from the registry; beginning scans for unsigned PE files." 
			<< std::endl;

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
		for(auto pair : notsigned){
			unsignedfile << L"File " << pair.first << L" is unsigned; referenced by:" << std::endl;
			for(auto value : pair.second){
				unsignedfile << "\t" << value.key.GetName() << L": " << value.GetPrintableName() << std::endl;
			}
			paths.emplace(pair.first);
		}
	}

	void EnumerateValuesRecursive(
		_In_ const Registry::RegistryKey& base,
		_Out_ std::unordered_map<std::wstring, std::vector<Registry::RegistryValue>>& found,
		_Out_ std::unordered_set<std::wstring>& explored,
		_In_opt_ const CriticalSection& hFoundGuard,
		_In_opt_ const CriticalSection& hExploredGuard,
		_In_opt_ bool multithreaded,
		_In_opt_ const std::function<std::vector<std::wstring>(_In_ const Registry::RegistryValue& value)>& identifier
	){

		auto path{ base.GetName() };

		EnterCriticalSection(hExploredGuard);
		if(explored.find(path) != explored.end()){
			LeaveCriticalSection(hExploredGuard);
			return;
		}
		explored.emplace(path);
		LeaveCriticalSection(hExploredGuard);

		auto values{ base.EnumerateValues() };
		for(const auto& value : values){
			auto val{ Registry::RegistryValue::Create(base, value) };
			if(val){
				auto strings{ identifier(*val) };
				for(auto& string : strings){
					EnterCriticalSection(hFoundGuard);
					if(found.find(string) == found.end()){
						found.emplace(string, std::vector<Registry::RegistryValue>{});
					}
					found.at(string).emplace_back(*val);
					LeaveCriticalSection(hFoundGuard);
				}
			}
		}

		auto subkeys{ base.EnumerateSubkeys() };
		for(const auto& subkey : subkeys){
			if(multithreaded){
				ThreadPool::GetInstance().EnqueueTask(
					[subkey, &found, &hFoundGuard, &explored, &hExploredGuard, identifier](){
						EnumerateValuesRecursive(subkey, found, explored, hFoundGuard, hExploredGuard, true, identifier);
					});
			} else {
				EnumerateValuesRecursive(subkey, found, explored, hFoundGuard, hExploredGuard, false, identifier);
			}
		}
	}
}