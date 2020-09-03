#include "DEEPGLASS/EnumRegistry.h"
#include "DEEPGLASS/Filtering.h"

#include "util/ThreadPool.h"

#include <iostream>
#include <fstream>

void main(){
	std::unordered_map<std::wstring, std::vector<Registry::RegistryValue>> found{};
	std::unordered_set<std::wstring> explored;
	CriticalSection hFoundGuard{}, hExploredGuard{};
	DEEPGLASS::EnumerateValuesRecursive(HKEY_LOCAL_MACHINE, found, explored, hFoundGuard, hExploredGuard, true);
	DEEPGLASS::EnumerateValuesRecursive(HKEY_USERS, found, explored, hFoundGuard, hExploredGuard, true);

	ThreadPool::GetInstance().Wait();

	CriticalSection output;
	std::wofstream bad{ L"./DEEPGLASS-unsigned.txt" };
	std::wofstream missing{ L"./DEEPGLASS-missing.txt" };

	for(const auto& pair : found){
		ThreadPool::GetInstance().EnqueueTask([pair, &output, &bad, &missing](){
			auto name{ pair.first };
			auto file{ DEEPGLASS::CreateFileObject(name) };
			if(file){
				if(!file->GetFileSigned()){
					EnterCriticalSection(output);
					bad << L"File " << file->GetFilePath() << L" was unsigned and referenced by the following values"
						<< std::endl;
					for(const auto& value : pair.second){
						bad << L"\t" << value.key.GetName() << ": " << value.wValueName << std::endl;
					}
					LeaveCriticalSection(output);
				}
			} else{
				EnterCriticalSection(output);
				missing << L"Unable to find " << name << std::endl;
				LeaveCriticalSection(output);
			}
		});
	}

	ThreadPool::GetInstance().Wait();
}