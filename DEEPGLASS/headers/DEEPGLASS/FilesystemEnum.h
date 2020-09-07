#pragma once

#include <Windows.h>

#include <unordered_set>

#include "util/wrappers.hpp"

namespace DEEPGLASS {

	/*!
	 * \brief Scans the filesystem for any evidence of search path hijacking, DLL sideloading, or unsigned binaries
	 *        in places where all binaries should be signed.
	 * 
	 * \details Scans the WinSxS directory and subdirectories with CheckWinSxS and all directories listed in %PATH%
	 *          for any unsigned executable files. Note that this function cannot be queued as a task in the ThreadPool,
	 *          nor should any tasks be running concurrently in the ThreadPool when this function is called. Note that 
	 *          no function should attempt to asynchronously modify `filenames` while CheckPath is running.
	 * 
	 * \param[out] paths A vector to which all file paths referring to unsigned PEs found will be written
	 */
	void RunFileChecks(_Out_ std::unordered_set<std::wstring>& paths);

	/*!
	 * \brief Scans all files in each folder in %PATH% for any unsigned PEs.
	 * 
	 * \details Enumerates directories in %PATH% and their WoW64 mirror, if present. Note that if DEEPGLASS is run in
	 *          WoW64, then this will not properly scan the 64-bit locations. If %PATH% is unset, this will default to 
	 *          reading C:\, C:\Windows, System32, C:\Windows\System32\wbem, C:\Windows\System32\WindowsPowerShell\v1.0,
	 *          C:\Windows\System, and their WoW64 mirrors. Note that no function should attempt to asynchronously 
	 *          modify `filenames` while CheckPath is running.
	 * 
	 * \param[out] filenames A vector to which all file paths referring to unsigned PEs found will be written
	 */
	void CheckPath(_Out_ std::unordered_set<std::wstring>& filenames);

	/*!
	 * \brief Scans all files in the specified folder for unsigned PEs and queues scans for all subdirectories
	 * 
	 * \details Scans all files in the directory referenced by `folder` for unsigned PEs. If an unsigned file is found,
	 *          it will be added to `filenames`. This function will be called on each subfolder found in the directory
	 *          in a separate thread, resulting in a recursive directory search for unsigned files. Note that the 
	 *          completion of the function does not mean that all subdirectory scans are finished; instead, wait for
	 *          all tasks in the threadpool to finish. hGuard and filenames must both not be destroyed until the last
	 *          subdirectory's scan has finished. This function is currently intended to only be used by CheckWinSxS.
	 * 
	 * \todo Accept a semaphore to track number of subdirectories not finished being scanned rather than relying on
	 *       emptying the threadpool.
	 * 
	 * \param[in]  folder    The path to the directory to begin the scan
	 * \param[in]  hGuard    A critical section guarding access
	 * \param[out] filenames A vector to which all file paths referring to unsigned PEs found will be written
	 */
	void CheckFolder(_In_ const std::wstring& folder, _In_ const CriticalSection& hGuard,
					 _Out_ std::unordered_set<std::wstring>& filenames);

	/*!
	 * \brief Scans all files part of the Windows Side-by-Side subsystem for unsigned PEs, indicative of sideloading.
	 * 
	 * \details Uses CheckFolder to scan C:\Windows\WinSxS and all subdirectories for any unsigned PEs.
	 * 
	 * \param[out] filenames A vector to which all file paths referring to unsigned PEs found will be written
	 */
	void CheckWinSxS(_Out_ std::unordered_set<std::wstring>& filenames);

	/*!
	 * \brief Utility function for scanning a list of file paths, outputting the results to a file, and adding paths 
	 *        referring to unsigned files to a second list.
	 * 
	 * \details ScanFiles iterates the file paths provided to it. If `check` is true, for each file path, an task
	 *          will be queued to the ThreadPool to check if the file is an unsigned PE. This function handles waiting
	 *          for all relevant tasks in the threadpool to finish. If the file is an unsigned PE, it will be added to
	 *          `paths` and printed to the file specified by `path`. If `check` is false, the file will be assumed to
	 *          be an unsigned PE and automatically recorded.
	 * 
	 * \param[in]  files A vector of file paths to check and / or record
	 * \param[out] paths A vector to which all file paths referring to unsigned PEs found will be written
	 * \param[in]  path  The path to the file to which the paths of unsigned PE files will be written
	 * \param[in]  check Indicates whether the provided file paths should be assumed to be unsigned PEs or not.
	 */
	void ScanFiles(_In_ const std::unordered_set<std::wstring>& files, _Out_ std::unordered_set<std::wstring>& paths,
				   _In_ const std::wstring& path, _In_opt_ bool check = true);
}