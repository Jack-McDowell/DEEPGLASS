
#include "util/configurations/RegistryValue.h"
#include "util/filesystem/FileSystem.h"

#include <iterator>
#include <iostream>

namespace DEEPGLASS {

	/*!
	 * \brief Deletes a directory and everything in it
	 * 
	 * \param path Path of the directory that will be deleted
	 * 
	 * \return True if the directory was successfully deleted; false otherwise
	 */
	bool DeleteDirectory(_In_ const std::wstring& path){
		// adapted from http://blog.nuclex-games.com/2012/06/how-to-delete-directories-recursively-with-win32/
		std::vector<std::wstring::value_type> terminated{};
		std::copy(path.begin(), path.end(), std::back_inserter(terminated));
		terminated.push_back(L'\0');
		terminated.push_back(L'\0');

		SHFILEOPSTRUCTW fileOperation{};
		fileOperation.wFunc = FO_DELETE;
		fileOperation.pFrom = &terminated[0];
		fileOperation.fFlags = FOF_NO_UI | FOF_NOCONFIRMATION;

		return !SHFileOperationW(&fileOperation);
	}

	bool InitializeDirectory(){
		DWORD attrs{ GetFileAttributesW(L".\\DEEPGLASS-Results") };
		if(attrs & FILE_ATTRIBUTE_DIRECTORY && attrs != INVALID_FILE_ATTRIBUTES){
			if(!DeleteDirectory(L".\\DEEPGLASS-Results")){
				return false;
			}
		}

		if(!CreateDirectoryW(L".\\DEEPGLASS-Results", nullptr)){
			return false;
		}

		if(!CreateDirectoryW(L".\\DEEPGLASS-Results\\Files", nullptr)){
			return false;
		}

		return true;
	}

	void MoveFiles(_In_ const std::unordered_set<std::wstring>& notsigned){
		for(const auto& path : notsigned){
			auto last{ path.find_last_of(L"\\/") };
			auto name{ path.substr(last == std::wstring::npos ? 0 : last + 1) };
			if(!CopyFileW(path.c_str(), (L".\\DEEPGLASS-Results\\Files\\" + name).c_str(), false)){
				std::wcerr << L"Failed to copy file at " << path << " to .\\DEEPGLASS-Results\\Files\\" << name << std::endl;
			}
		}
	}
};