#pragma once

#include <Windows.h>

#include <unordered_map>
#include <vector>
#include <string>
#include <functional>

#include "Filtering.h"

namespace DEEPGLASS {

	/*!
	 * \brief Enumerates values and subkeys under a given registry key, searching for values whose data meets
	 *        some condition, which defaults to searching for file paths referring to PE files.
	 * 
	 * \details EnumerateValuesRecursive creates RegistryValue objects for all values under a given key and passes
	 *          them into the supplied identifier function. Each result from the identifier function is then added
	 *          into the map of things found by the identifier. The associated registry value is also added into the
	 *          result's entry in the map. Then EnumerateValuesRecursive is called on each subkey of the given key.
	 *          EnumerateValuesRecursive may run sequentially or multithreaded. When run multithreaded, the user must
	 *          provide CriticalSection objects for both `found` and `explored` (`hFoundGuard` and `hExploredGuard`
	 *          respectively). Further, `found`, `explored`, `hFoundGuard`, and `hExploredGuard` must not be destroyed
	 *          all threads are finished executing. Additionally, if the user wishes to use `found` or `explored` 
	 *          during the execution of this function, the user must first acquire `hFoundGuard` or `hExploredGuard` 
	 *			respectively.
	 * 
	 * \param[in]  base        T   he registry key to search under
	 * \param[out] found          A mapping of results from the identifier function to the registry values under which 
	 *                            they were found. 
	 * \param[out] explored       A set containing the names of all registry keys visited. 
	 * \param[in]  hFoundGuard    A critical section object for guarding accesses to `found`. Required only if 
	 *                            `multithreaded` is set to true.
	 * \param[in]  hExploredGuard A critical section object for guarding accesses to `explored`. Required only if 
	 *                            `multithreaded` is set to true.
	 * \param[in]  multithreaded  True if this function should be run multithreaded; false otherwise. Defaults to false
	 * \param[in]  identifier     The function used to identify values and data of interest. Defaults to 
	 *                            FindReferencedFiles, with IsFiletypePE bound as the file filter.
	 */
	void EnumerateValuesRecursive(
		_In_ const Registry::RegistryKey& base,
		_Out_ std::unordered_map<std::wstring, std::vector<Registry::RegistryValue>>& found,
		_Out_ std::unordered_set<std::wstring>& explored,
		_In_opt_ const CriticalSection& hFoundGuard = {},
		_In_opt_ const CriticalSection& hExploredGuard = {},
		_In_opt_ bool multithreaded = false,
		_In_opt_ const std::function<std::vector<std::wstring>(_In_ const Registry::RegistryValue& value)>& identifier =
		std::bind(FindReferencedFiles, std::placeholders::_1, IsFiletypePE)
	);

	/*!
	 * \brief Scans the registry for PE files, providing a list of unsigned files found in the registry and printing 
	 *        lists of unsigned files and files referenced but not found to files. 
	 * 
	 * \details Uses EnumerateValuesRecursive to identify file paths stored in the data of registry values. Each file
	 *          path or name is checked to determine whether it likely refers to an executable. Any file or path 
	 *          identified is then checked. If the file is not found, its name and associated registry values get 
	 *          written to .\DEEPGLASS-Results\Registry-Missing-Files.txt. Alternatively, if the file is found but
	 *          unsigned, it is added to `paths`, and both it and its associated registry values get written to
	 *          .\DEEPGLASS-Results\Registry-Unsigned-Files.txt
	 * 
	 * \param[out] paths Any file name or path referring to an unsigned file will be added to this set.
	 */
	void RunRegistryChecks(_Out_ std::unordered_set<std::wstring>& paths);
};