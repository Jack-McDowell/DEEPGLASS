#pragma once

#include <Windows.h>

#include <vector>
#include <string>

#include "util/configurations/RegistryValue.h"

namespace DEEPGLASS{
	
	/*!
	 * \brief Initializes the directory where DEEPGLASS output files will be stored
	 * 
	 * \details Checks for the presence of a DEEPGLASS-Results folder in the current directory. If the folder is 
	 *          present, then it and all of its contents will be removed. Then it creates a new DEEPGLASS-Results
	 *          directory, which will hold all outputs from DEEPGLASS.
	 * 
	 * \return True if the directory was successfully initialized; false otherwise.
	 */
	bool InitializeDirectory();

	/*!
	 * \brief Copies all unsigned files identified into the DEEPGLASS-Results directory for further analysis
	 * 
	 * \param notsigned A set containing the paths of unsigned files to be copied to the DEEPGLASS-Results directory
	 */
	void MoveFiles(_In_ const std::unordered_set<std::wstring>& notsigned);
}