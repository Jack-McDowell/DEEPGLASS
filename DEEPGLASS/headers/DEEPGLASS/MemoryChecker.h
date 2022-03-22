#pragma once

#include <Windows.h>

#include <unordered_set>
#include <unordered_map>
#include <vector>

namespace DEEPGLASS {

    /*!
     * \brief Scans all process' loaded modules, filling the provided map with modules and associated PIDs.
     * 
     * \details ScanLoadedModules enumerates all processes and their loaded modules. Each module found is added to the 
     *          provided map, and each process that has that module loaded will have its PID added to the set 
     *          associated with that module's name in the map. This function enumerates modules asynchronously but will
     *          not return until all processes have their modules enumerated.
     * 
     * \param[out] found Receives the loaded modules and their associated PIDs
     */
    void ScanLoadedModules(_Out_ std::unordered_map<std::wstring, std::unordered_set<DWORD>>& found);

    /*!
     * \brief Scans the provided file paths to check if they refer to unsigned PEs, and if so, record the path in the 
     *        provided set and write the file path and associated PIDs to file whose path is provided
     * 
     * \details Scans the file paths provided as keys in `files` to check if the file to which they refer is an 
     *          unsigned PE. If so, the file path will be added to `paths`. The file path will be written to the file
     *          whose path is specified by `path`. Additionally, each PID in the set associated with the file path 
     *          in `files` will be written to the file. This function performs the scans asynchronously but will not
     *          return until all scans have completed.
     *
     * \param[in]  files A mapping of file paths to PIDs associated with the file path
     * \param[out] paths A set that will receive the paths of all unsigned PEs included in `files`
     * \param[in]  path  The path to the file to which unsigned file paths will be written
     */
    void ScanFilesWithPIDs(_In_ const std::unordered_map<std::wstring, std::unordered_set<DWORD>>& files,
                           _Out_ std::unordered_set<std::wstring>& paths, _In_ const std::wstring& path);

    /*!
     * \brief Scans all handles open in all processes for file handles, filling the provided map with handles and
     *        their associated processes.
     * 
     * \details EnumerateHandles enumerates every handle open on the system, using Internals::GetHandleName to find
     *          the name of the handle. The system file paths are then replaced with the DOS file path referring to
     *          the same file. Each file name found will be added as a key to `found`, and each process found with a 
     *          handle to the file will be added to the associated set. Note that since this function uses 
     *          Internals::GetHandleName, it cannot be run asynchronously at the same time as another function using
     *          Internals::GetHandleName or Internals::QueryName.
     * 
     * \param[out] found A mapping of file paths to files found in open handles to a set of PIDs associated with the
     *                   processes with an open handle to the file.
     */
    void EnumerateHandles(_Out_ std::unordered_map<std::wstring, std::unordered_set<DWORD>>& found);

    /*!
     * \brief Scans all open handles by enumerating them with EnumerateHandles then passing the results to 
     *        ScanFilesWithPIDs. Also cross-references every file path in `files` with open handles, writing the file
     *        paths found in both to a file
     * 
     * \param[inout] files A set containing all other files identified as unsigned PEs by DEEPGLASS, which will 
     *                     receive all file paths identified in the handle table             
     */
    void ScanHandleTables(_Inout_ std::unordered_set<std::wstring>& files);

    /*!
     * \brief Scans loaded modules by running ScanLoadedModules and passing the results to ScanFilesWithPIDs. Then runs
     *        ScanHandleTables.
     * 
     * \param[inout] files A set containing all other files identified as unsigned PEs by DEEPGLASS, which will 
     *                     receive all file paths identified in the handle table   
     */
    void RunMemoryChecks(_Inout_ std::unordered_set<std::wstring>& files);
}