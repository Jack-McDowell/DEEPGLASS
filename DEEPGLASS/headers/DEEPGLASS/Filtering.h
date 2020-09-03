#pragma once

#include <Windows.h>

#include <vector>
#include <string>
#include <functional>

#include "util/configurations/RegistryValue.h"
#include "util/filesystem/FileSystem.h"

namespace DEEPGLASS{

	/*!
	 * \brief Checks if a file is a PE by reading its contents and comparing to the PE32+ standard.
	 *
	 * \param[in] file The file to check
	 *
	 * \return True if the file is a portable executable file; false if the file is not found, cannot be read,
			   or does not conform to the PE32+ standard.
	 */
	bool IsPEFile(_In_ const FileSystem::File& file);

	/*!
	 * \brief Determines if the file path provided refers to a PE file.
	 *
	 * \details First, this checks if the file exists, and if so, checks if the file is a PE using the IsPEFile
				function. Otherwise, if the full path of the file is provided (including the DOS device), then
				the determination is made solely based on the file extension, if present. Otherwise, directories
				in %PATH% are searched for a file matching the file name. If a file is found, it is checked using
				IsPEFile; otherwise, it will be determined to not be an executable file.
	 *
	 * \param[in] filename The name or path of the file to be searched.
	 *
	 * \return True if the file is a PE file; false if the file is not a PE file or a determination could not be made.
	 */
	bool IsFiletypePE(_In_ const std::wstring& filename);

	/*!
	 * \brief Identifies possible referenced files contained in a registry value's data.
	 *
	 * \details This function scans the provided RegistryValue for possible files stored in the value's data.
	 *			Results can be further filtered with an optional filter, which defaults to only including PE files, 
	 *          as defined in IsFiletypePE.
	 *
	 * \param[in] value  The registry value whose data will be searched for references to files
	 * \param[in] filter An optional filter to limit files identified to those meeting a certain condition.
	 *
	 * \return A vector containing the files that may be referenced in the value's data
	 */
	std::vector<std::wstring> FindReferencedFiles(
		_In_ const Registry::RegistryValue& value,
		_In_opt_ const std::function<bool(_In_ const std::wstring& potential)>& filter = IsFiletypePE);

	/*!
	 * \brief Attempts to find and create an object for the associated file for a given file name
	 * 
	 * \details 
	 * 
	 * \param[in] filename The name of the file to try to find and create an object for
	 * 
	 * \return An optional containing a file object for the specified file; nullopt if the file couldn't be found
	 */
	std::optional<FileSystem::File> CreateFileObject(_In_ const std::wstring& filename);
};