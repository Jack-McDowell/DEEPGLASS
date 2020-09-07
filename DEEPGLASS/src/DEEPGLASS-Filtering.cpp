#include "DEEPGLASS/Filtering.h"

#include "util/configurations/Registry.h"
#include "util/configurations/RegistryValue.h"
#include "util/filesystem/FileSystem.h"
#include "util/log/Log.h"
#include "util/StringUtils.h"
#include "util/ThreadPool.h"

#include <vector>
#include <regex>
#include <string>

#include <shlwapi.h>

namespace DEEPGLASS{

	bool IsPEFile(_In_ const FileSystem::File& file){
		if(file.GetFileExists()){
			if(!file.HasReadAccess()){
				LOG_WARNING(L"Unable to properly scan " << file << L" due to lack of read access.");
				return false;
			}

			auto headers{ file.Read(0x400) };
			MemoryWrapper<> memory{ static_cast<LPVOID>(headers), headers.GetSize() };
			if(!headers || *memory.Convert<WORD>() != 0x5A4D){
				return false;
			}

			DWORD offset{ *memory.GetOffset(0x3C).Convert<DWORD>() };
			if(offset + 4 >= 0x400){
				LOG_INFO(2, "File " << file << " may conform to the PE32+ standard, but it is not a normal PE.");
				return false;
			}

			return *memory.GetOffset(offset).Convert<DWORD>() == 0x4550UL;
		} else{
			return false;
		}
	}

	bool IsFiletypePE(_In_ const std::wstring& filename){
		if(FileSystem::CheckFileExists(filename)){
			return IsPEFile(FileSystem::File{ filename });
		}

		auto endptr{ PathFindExtensionW(filename.data()) };
		if(endptr && *endptr){
			std::wstring ext{ endptr };
			if(ext == L".exe" || ext == L".dll" || ext == L".ocx" || ext == L".sys"){
				return true;
			} else{
				return false;
			}
		} else{
			if(filename.size() >= 2 && filename.at(1) == L':'){
				return false;
			} else{
				auto search{ FileSystem::SearchPathExecutable(filename) };
				if(search && *search != filename){
					return IsFiletypePE(*search);
				} else{
					return false;
				}
			}
		}
	}

	std::vector<std::wstring> FindReferencedFiles(
		_In_ const Registry::RegistryValue& value,
		_In_opt_ const std::function<bool(_In_ const std::wstring& potential)>& filter){

		if(value.GetType() == RegistryType::REG_MULTI_SZ_T){
			std::vector<std::wstring> strings{};
			for(const auto& entry : std::get<std::vector<std::wstring>>(value.data)){
				auto copy{ entry };
				auto result{ FindReferencedFiles(
					Registry::RegistryValue{ value.key, value.wValueName, std::move(copy) }, filter) };
				for(const auto& x : result){
					strings.emplace_back(x);
				}
			}
			return strings;
		} else if(value.GetType() == RegistryType::REG_EXPAND_SZ_T || value.GetType() == RegistryType::REG_SZ_T){
			std::vector<std::wstring> files{};
			std::wregex regex{ L"[a-zA-Z]:([/\\\\]?[a-zA-Z0-9().% #'@_\\-\\^]+)+,?" };
			auto strs{ std::get<std::wstring>(value.data) };
			for(auto data : SplitStringW(strs, L";")){
				if(data.length()){
					std::wsmatch match{};
					if(std::regex_search(data, match, regex)){
						for(auto& filename : match){
							if(filename.str().length() >= 1 && *(filename.str().end() - 1) != L',' &&
							   filter(filename.str())){
								auto f{ CreateFileObject(filename.str()) };
								files.emplace_back(ToLowerCaseW(f ? f->GetFilePath() : filename.str()));
							}
						}
					} else{
						if(data.find(L' ') == std::wstring::npos || (data.size() >= 4 && *(data.end() - 4) == L'.')){
							if(filter(data)){
								auto f{ CreateFileObject(data) };
								files.emplace_back(ToLowerCaseW(f ? f->GetFilePath() : data));
							}
						}
					}
				}
			}
			return files;
		}

		return {};
	}

	std::optional<FileSystem::File> CreateFileObject(_In_ const std::wstring& filename){
		auto expanded{ filename };
		if(expanded.size() >= 11 && expanded.substr(0, 11) == L"\\SystemRoot"){
			expanded = L"%SYSTEMROOT%" + expanded.substr(11);
		}
		if(expanded.size() >= 4 && expanded.substr(0, 4) == L"C:\\?"){
			expanded = expanded.substr(0, 3) + expanded.substr(4);
		}
		expanded = ExpandEnvStringsW(expanded);
		if(expanded.at(0) == L'\\'){
			expanded = expanded.substr(1);
		}

		if(FileSystem::CheckFileExists(expanded)){
			return FileSystem::File{ expanded };
		} else{
			auto path{ FileSystem::SearchPathExecutable(expanded) };
			if(path){
				return *path;
			} else{
				return std::nullopt;
			}
		}
	}

	void FilterSigned(_In_ const std::unordered_map<std::wstring, std::vector<Registry::RegistryValue>>& found,
					  _Out_ std::vector<std::pair<std::wstring, std::vector<Registry::RegistryValue>>>& notsigned,
					  _Out_ std::vector<std::pair<std::wstring, std::vector<Registry::RegistryValue>>>& notfound){
		std::vector<Promise<bool>> promises{};
		CriticalSection hSignedGuard{}, hFoundGuard{};
		auto& instance{ ThreadPool::GetInstance() };
		for(const auto pair : found){
			promises.emplace_back(
				instance.RequestPromise<bool>([pair, &notsigned, &notfound, &hSignedGuard, &hFoundGuard](){
					auto file{ CreateFileObject(pair.first) };
					if(file){
						if(!file->GetFileSigned()){
							EnterCriticalSection(hSignedGuard);
							notsigned.emplace_back(pair);
							LeaveCriticalSection(hSignedGuard);
						} 
					} else{
						EnterCriticalSection(hFoundGuard);
						notfound.emplace_back(pair);
						LeaveCriticalSection(hFoundGuard);
					}
					return 0;
				}));
		}
		for(const auto& promise : promises){
			promise.GetValue();
		}
	}
};