#include "DEEPGLASS/FilesystemEnum.h"

#include <Windows.h>

#include <unordered_set>
#include <string>
#include <fstream>
#include <iostream>

#include "util/filesystem/FileSystem.h"
#include "util/ThreadPool.h"
#include "util/StringUtils.h"

#include "DEEPGLASS/Filtering.h"

namespace DEEPGLASS{
    void CheckPath(_Out_ std::unordered_set<std::wstring>& filenames){
        std::cout << "Scanning path for unsigned files" << std::endl;
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

        for(const auto& directory : locations){
            auto folder{ ExpandEnvStringsW(directory) };
            std::wcout << "\t" << "Reading files from " << directory << std::endl;

            // Don't use filesystem module since it creates a File object for each file found
            WIN32_FIND_DATA ffd{};
            FindWrapper find{ FindFirstFileW((folder + L"\\*").c_str(), &ffd) };
            if(find){
                do{
                    if(ffd.cFileName != std::wstring{ L"." } && ffd.cFileName != std::wstring{ L"." } &&
                       ffd.dwFileAttributes != (DWORD) -1 && !(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)){
                        filenames.emplace(ToLowerCaseW(folder + L"\\" + ffd.cFileName));
                    }
                } while(FindNextFileW(find, &ffd));
            }
        }
    }

    void CheckFolder(_In_ const std::wstring& folder, _In_ const CriticalSection& hGuard,
                     _Out_ std::unordered_set<std::wstring>& filenames){

        // Use custom directory traversal to drastically speed things up and 
        WIN32_FIND_DATA ffd{};
        FindWrapper find{ FindFirstFileW((folder + L"\\*").c_str(), &ffd) };
        if(find){
            do{
                if(ffd.cFileName != std::wstring{ L"." } && ffd.cFileName != std::wstring{ L".." } &&
                   ffd.dwFileAttributes != (DWORD) -1){
                    auto name{ folder + L"\\" + ffd.cFileName };
                    if(ffd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY){
                        ThreadPool::GetInstance().EnqueueTask([name, &hGuard, &filenames](){
                            CheckFolder(name, hGuard, filenames);
                        });
                    } else {
                        FileSystem::File file{ name };
                        if(IsPEFile(file) && !file.GetFileSigned()){
                            EnterCriticalSection(hGuard);
                            filenames.emplace(ToLowerCaseW(name));
                            LeaveCriticalSection(hGuard);
                        }
                    }
                }
            } while(FindNextFileW(find, &ffd));
        }
    }

    void CheckWinSxS(_Out_ std::unordered_set<std::wstring>& filenames){
        std::cout << "Scanning WinSxS for sideloading files" << std::endl;
        CriticalSection hGuard{};
        CheckFolder(ExpandEnvStringsW(L"%SystemRoot%\\WinSxS"), hGuard, filenames);
        ThreadPool::GetInstance().Wait();
    }

    void ScanFiles(_In_ const std::unordered_set<std::wstring>& files, _Out_ std::unordered_set<std::wstring>& paths, 
                   _In_ const std::wstring& path, _In_opt_ bool check){
        std::vector<Promise<bool>> promises{};
        std::wofstream unsignedfile(path);
        CriticalSection hGuard{};
        for(const auto file : files){
            if(check){
                promises.emplace_back(
                    ThreadPool::GetInstance().RequestPromise<bool>([file, &hGuard, &unsignedfile, &paths](){
                        if(DEEPGLASS::IsFiletypePE(file) && !FileSystem::File{ file }.GetFileSigned()){
                            EnterCriticalSection(hGuard);
                            paths.emplace(ToLowerCaseW(file));
                            unsignedfile << L"File " << file << L" is unsigned" << std::endl;
                            LeaveCriticalSection(hGuard);
                        }
                        return true;
                    })
                );
            } else{
                paths.emplace(ToLowerCaseW(file));
                unsignedfile << L"File " << file << L" is unsigned" << std::endl;
            }
        }
        for(const auto& promise : promises){
            promise.GetValue();
        }
    }

    void RunFileChecks(_Out_ std::unordered_set<std::wstring>& paths){
        std::unordered_set<std::wstring> files{};

        CheckPath(files);
        ScanFiles(files, paths, L".\\DEEPGLASS-Results\\Path-Unsigned-Files.txt", true);
        files.clear();

        CheckWinSxS(files);
        ScanFiles(files, paths, L".\\DEEPGLASS-Results\\WinSxS-Unsigned-Files.txt", false);
        files.clear();
    }
};