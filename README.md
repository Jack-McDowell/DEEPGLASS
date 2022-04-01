# DEEPGLASS

DeepGlass picks up where [BLUESPAWN](https://github.com/ION28/BLUESPAWN) leaves off, performing an extensive system scan. DEEPGLASS has scans available for the system registry, filesystem, and memory / active processes. Each is described below.

 * **Registry**: Each value stored in the registry is enumerated and scanned to determine whether or not it refers to a PE file. If it does, the file is scanned.
 * **Filesystem**: Each file located in any directory listed in `%PATH%` is scanned. Additionally, all files that are part of the WinSxS subsystem are scanned.
 * **Memory / Active Processes**: All open file handles and loaded modules are scanned. Furthermore, all PEs loaded into memory are scanned and compared to their associated files. Any PE with more than 500 bytes different from the associated file will be recorded.

Note that the image coherency checking described above is not meant to catch all in-memory attacks; its sole purpose is to identify any malware that's attempting to disguise itself as a legitimate DLL or EXE in memory. In particular, it will not catch hooks operating through code patches or IAT modifications, nor will it catch shellcode blobs dropped in memory. Another forthcoming module will address the latter issue.
 
### A Note
DEEPGLASS is complimentary to BLUESPAWN in that it will likely be able to identify things missed by BLUESPAWN, but it is not a replacement. DEEPGLASS is meant to give a defender a lay of the land or a forensic investigator a quick starting point for any investigation of an infected system rather than provide defensive options. Further, BLUESPAWN has much more detailed detections, scanning capabilities, and reactions and will be able to catch obfuscation techniques that DEEPGLASS will miss.

DEEPGLASS scans also take longer to finish and have significantly more false positives than BLUESPAWN.

## Usage

```cmd
DEEPGLASS.exe
```

The results will be written to `.\DEEPGLASS-Results`. Text documents summarizing the results of each scan will be written to that directory, and all files identified as potentially malicious will be copied to `.\DEEPGLASS-Results\Files`.

## Documentation

Each function in DEEPGLASS has doxygen comments describing how the function works.
