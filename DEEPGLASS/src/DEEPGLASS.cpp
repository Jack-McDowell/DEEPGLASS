#include "DEEPGLASS/EnumRegistry.h"
#include "DEEPGLASS/Filtering.h"
#include "DEEPGLASS/FileCollector.h"
#include "DEEPGLASS/FilesystemEnum.h"
#include "DEEPGLASS/MemoryChecker.h"

#include <iostream>

void main(){
	if(!DEEPGLASS::InitializeDirectory()){
		std::cerr << "Failed to initialize directory for outputs; aborting!" << std::endl;
	} else {
		std::unordered_set<std::wstring> files{};

		DEEPGLASS::RunRegistryChecks(files);
		DEEPGLASS::RunFileChecks(files);
		DEEPGLASS::RunMemoryChecks(files);

		DEEPGLASS::MoveFiles(files);
	}
}