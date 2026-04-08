## hpcap

This is a placeholder repository for high perfermance "hft" style pcap reader and iterator for c++.

This project will contain a high performance implementation that builds on the works of:

https://www.tcpdump.org

https://pcapplusplus.github.io


## The Open Markets Initiative

[The Open Markets Initiative](https://github.com/Open-Markets-Initiative/Directory/tree/main/About "About Omi") (Omi) is an organization dedicated to enhancing the stability of electronic financial markets using modern development methods.

[![Omi](https://github.com/Open-Markets-Initiative/Directory/blob/main/About/Images/Logo.png)](https://github.com/Open-Markets-Initiative/Directory/tree/master/About)

## Student Projects

The OMI is creating a series of projects for students in computer science in the US.

AI use and professional coding processes are encouraged.

## Build

This repository now builds as a standalone CMake project.

Configure:

```powershell
cmake -S . -B build
```

Build:

```powershell
cmake --build build
```

Optional compression backends can be enabled at configure time:

```powershell
cmake -S . -B build -DHPCAP_ENABLE_ZLIB=ON -DHPCAP_ENABLE_BZIP2=ON -DHPCAP_ENABLE_LZMA=ON
```

## Example Runner

The example runner reads one or more pcap files and prints a short packet summary:

```powershell
.\build\pcap_runner.exe C:\path\to\capture.pcap
```

## Unit Tests

Run the initial unit test suite with CTest:

```powershell
ctest --test-dir build --output-on-failure
```
