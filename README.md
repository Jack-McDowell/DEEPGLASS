# DEEPGLASS

DeepGlass picks up where BLUESPAWN leaves off, performing an extensive system scan. DEEPGLASS has scans available for the system registry, filesystem, and memory / active processes. Each is described below.

 * **Registry**: Each value stored in the registry is enumerated and scanned to determine whether or not it refers to a PE file. If it does, the file is scanned.
 * **Filesystem**: Each file located in any directory listed in `%PATH%` is scanned. Additionally, all files that are part of the WinSxS subsystem are scanned.
 * **Memory / Active Processes**: All open file handles and loaded modules are scanned.

## Usage

```cmd
DEEPGLASS.exe
```

The results will be written to `.\DEEPGLASS-Results`. Text documents summarizing the results of each scan will be written to that directory, and all files identified as potentially malicious will be copied to `.\DEEPGLASS-Results\Files`.

## Documentation

Each function in DEEPGLASS has doxygen comments describing how the function works.