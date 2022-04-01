#include "DEEPGLASS/MemoryConsistency.h"

#include <Windows.h>
#include <Psapi.h>
#include <stddef.h>

#include "DEEPGLASS/Filtering.h"
#include "util/processes/ProcessUtils.h"
#include "util/Threadpool.h"

#include <iostream>
#include <vector>
#include <fstream>
#include <set>
#include <map>
#include <sstream>

#define RETURN_IF(val, ...) \
    if(__VA_ARGS__){        \
        return val;         \
    }

#define MAKE_CDATA(type) \
    ConsistencyData{ MapConsistency::##type, memBase }

#define MAKE_CDATA_C(type, ...) \
    ConsistencyData{ MapConsistency::##type, memBase, __VA_ARGS__ }

#define RVA_TO_RAW(raw) \
    (((raw) & 0xFFF) + rvaConverter.at((raw) & ~0xFFF))

LINK_FUNCTION(RtlSetCurrentTransaction, ntdll.dll)

namespace DEEPGLASS{

    struct RELOC_ENTRY {
        WORD    offset : 12;
        WORD    type : 4;
    };

    ConsistencyData::ConsistencyData(_In_ MapConsistency consistency) : consistency{ consistency }{}
    ConsistencyData::ConsistencyData(_In_ MapConsistency consistency, _In_ const MemoryWrapper<>& regionInfo,
                    _In_ const std::optional<std::wstring>& comment) :
        consistency{ consistency },
        baseAddress{ regionInfo.address },
        regionSize{ regionInfo.MemorySize },
        process{ regionInfo.process },
        comment{ comment }{}

    ConsistencyData::operator MapConsistency() const{ return consistency; }
    bool ConsistencyData::operator==(MapConsistency consistency) const{ return consistency == this->consistency; }
    bool ConsistencyData::operator!=(MapConsistency consistency) const{ return consistency != this->consistency; }

    ConsistencyData CheckSectionCoherency(_In_ MemoryWrapper<>& fileBase, _In_ MemoryWrapper<>& memBase){
        /* DOS headers should match exactly. */
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"DOS header mismatch"),
                  !fileBase.CompareMemory(memBase, sizeof(IMAGE_DOS_HEADER)));

        auto fileNt = fileBase.GetOffset(fileBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS64>();
        auto memNt = memBase.GetOffset(memBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS64>();

        /* Section count, architecture, and data directories should match exactly. */
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Section count mismatch"),
                  fileNt->FileHeader.NumberOfSections != memNt->FileHeader.NumberOfSections);
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Architecture mismatch"),
                  fileNt->FileHeader.Machine != memNt->FileHeader.Machine);
        
        /* Okay, technically this isn't needed as the file header is always the same, but whatever. */
        auto optHeaderOffset{
            IMAGE_FILE_MACHINE_AMD64 == fileNt->FileHeader.Machine ?
                offsetof(IMAGE_NT_HEADERS64, OptionalHeader) :
                offsetof(IMAGE_NT_HEADERS32, OptionalHeader) };

        auto imageSizeOffset{ optHeaderOffset + (fileNt->OptionalHeader.Magic == 0x020B ?
            offsetof(IMAGE_OPTIONAL_HEADER64, SizeOfImage) :
            offsetof(IMAGE_OPTIONAL_HEADER32, SizeOfImage)) };
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Image Size Mismatch"),
                  *fileNt.GetOffset(imageSizeOffset).Convert<DWORD>() != memBase.MemorySize);

        /* It'd be nice if we could handle this another way, but it would seem the optional header's architecture
         * does NOT necessarily match that of the file header... so we have to check again! */
        auto dataDirFileOffset{ optHeaderOffset + (fileNt->OptionalHeader.Magic == 0x020B ?
            offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) :
            offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory)) };

        /* Assume by default that the data directories will be the same in memory and in the file */
        auto dataDirMemOffset{ dataDirFileOffset };

        /* This is the offset in the file from the start of the NT headers to the .NET directory. */
        auto netDirOffset{ dataDirFileOffset + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_DIRECTORY_ENTRY_COM_DESCRIPTOR };

        /* See if the .NET directory has a size. If so, it's a .NET binary. */
        if (*fileNt.GetOffset(netDirOffset).GetOffset(offsetof(IMAGE_DATA_DIRECTORY, Size)).Convert<DWORD>()) {

            /* Sometimes .NET binaries will replace their own header with a different architecture for... reasons. */
            /* We want to accomodate this to avoid false positives. */
            dataDirMemOffset = optHeaderOffset + (memNt->OptionalHeader.Magic == 0x020B ?
                offsetof(IMAGE_OPTIONAL_HEADER64, DataDirectory) :
                offsetof(IMAGE_OPTIONAL_HEADER32, DataDirectory));
        }

        /* If the data directories mismatch, then a fake relocation table could be inserted to build an arbitrary
         * .text section that bypasses our checks. Technically this doesn't mean there's executable stuff hiding,
         * but since the data directory should never mismatch, we can check just to be safe. */
        bool dataMismatch{ !fileNt.GetOffset(dataDirFileOffset).CompareMemory(
            memNt.GetOffset(dataDirMemOffset), 
            sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES) };
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Data directory mismatch"), dataMismatch);

        auto cnt{ fileNt->FileHeader.NumberOfSections };

        /* Find pointers to the section headers using the address and size of the data directories */
        auto fileSections{ 
            fileNt.GetOffset(dataDirFileOffset + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
                .Convert<IMAGE_SECTION_HEADER>() };
        auto memSections{ 
            memNt.GetOffset(dataDirMemOffset + sizeof(IMAGE_DATA_DIRECTORY) * IMAGE_NUMBEROF_DIRECTORY_ENTRIES)
                .Convert<IMAGE_SECTION_HEADER>() };

        /* We're going to fill allowedExecutable with page number offsets of pages that are marked as executable in the
         * appropriate section headers. */
        std::set<DWORD> allowedExecutable{};

        for(auto i = 0; i < cnt; i++){
            auto memHdr{ *memSections };
            auto fileHdr{ *fileSections };

            /* Section headers should be unchanged (with certain exceptions). */
            bool sectionHeadersAcceptable{ true };
            sectionHeadersAcceptable = sectionHeadersAcceptable && memHdr.Characteristics == fileHdr.Characteristics;
            sectionHeadersAcceptable = sectionHeadersAcceptable && memHdr.VirtualAddress == fileHdr.VirtualAddress;
            sectionHeadersAcceptable = sectionHeadersAcceptable && memHdr.SizeOfRawData == fileHdr.SizeOfRawData;
            sectionHeadersAcceptable = sectionHeadersAcceptable && memHdr.Misc.VirtualSize == fileHdr.Misc.VirtualSize;
            sectionHeadersAcceptable = sectionHeadersAcceptable && 
                (memHdr.PointerToRawData == fileHdr.PointerToRawData || !fileHdr.SizeOfRawData);
            RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Section header mismatch"), !sectionHeadersAcceptable);
            
            /* Next section header, please */
            fileSections = fileSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
            memSections = memSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
        }

        return MAKE_CDATA(Consistent);
    }

    bool SimulateRelocations(_In_ MemoryWrapper<>& fileBase, _In_ LPVOID loadBase){
        auto fileNt{ fileBase.GetOffset(fileBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS64>() };

        IMAGE_DATA_DIRECTORY entry{};
        ULONG_PTR offset{};
        auto delta{ reinterpret_cast<ULONG_PTR>(loadBase) };

        /* We need to support both architectures here, and the optional header varies in size between architectures. */
        /* But the file header architecture can lie (thanks, .NET), so check the magic bytes instead. */
        if(fileNt->OptionalHeader.Magic == 0x020B){
            entry = fileNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            offset = sizeof(IMAGE_NT_HEADERS64);
            delta -= fileNt->OptionalHeader.ImageBase;
        } else{
            entry = fileNt.Convert<IMAGE_NT_HEADERS32>()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            offset = sizeof(IMAGE_NT_HEADERS32);
            delta -= fileNt.Convert<IMAGE_NT_HEADERS32>()->OptionalHeader.ImageBase;
        }

        /* If there are no relocations, return now! */
        if(!entry.Size){
            return true;
        }

        /* 
         * We need a way to translate between virtual address and raw addresses. We can do that by creating a map that
         * maps relative virtual addresses to their raw offsets, going page by page. Given any virtual address, then,
         * we can bitwise AND out the page offset and plug it into the map, and add the page offset onto the result
         * to get the raw offset. Build this map by going section by section and calculating the offsets.
         */
        auto cnt{ fileNt->FileHeader.NumberOfSections };
        auto fileSections = fileNt.GetOffset(offset).Convert<IMAGE_SECTION_HEADER>();
        std::map<DWORD, DWORD> rvaConverter{};
        for(auto i = 0; i < cnt; i++){
            for(auto j = fileSections->VirtualAddress; j < fileSections->VirtualAddress + fileSections->SizeOfRawData;
                j += 0x1000){

                /* Map the VirtualAddress of the section plus some offset to the PointerToRawData plus that offset */
                rvaConverter.emplace(j, j - fileSections->VirtualAddress + fileSections->PointerToRawData);
            }

            /* Unlike raw pointers, GetOffset always counts bytes, not instances of the pointee type. */
            fileSections = fileSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
        }

        /* If we can't find the raw offset of the relocation table, give up */
        if(rvaConverter.find(entry.VirtualAddress & ~0xFFF) == rvaConverter.end()){
            return false;
        }

        /* Use rvaConverter to convert the virtual address of the relocation table */
        offset = RVA_TO_RAW(entry.VirtualAddress);
        PIMAGE_BASE_RELOCATION relocations{ fileBase.GetOffset(offset).Convert<IMAGE_BASE_RELOCATION>() };
        

        /* relocations will refer to the currently process relocation block. The last will be empty. */
        while(relocations->SizeOfBlock && 
              reinterpret_cast<ULONG_PTR>(relocations) - reinterpret_cast<ULONG_PTR>(fileBase.address) 
                  < offset + entry.Size){

            if(rvaConverter.find(relocations->VirtualAddress) != rvaConverter.end()){

                /* 
                 * The virtual address of a relocation block is always a page aligned address, and all relocation
                 * entries therein are comprised of a page offset and a relocation type. Each relocation block
                 * consists of some number of relocation entries as determined by the SizeOfBlock property of the
                 * struct. We need to convert the block pointer (blockPtr) to a raw file offset, but since the
                 * same page is part of the same section and therefore will always have the same difference between
                 * the virtual address and file offset, each individual relocation does not need to be retranslated.
                 */
                auto blockPtr{ 
                    reinterpret_cast<ULONG_PTR>(fileBase.address) + RVA_TO_RAW(relocations->VirtualAddress) };

                /* SizeOfBlock refers to the number of bytes in the block. Exclude the struct itself. */
                auto cnt{ (relocations->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC_ENTRY) };
                auto entry{ reinterpret_cast<RELOC_ENTRY*>(relocations + 1) };

                for(auto i{ 0ul }; i < cnt; i++){
                    auto type{ entry->type };

                    /* Depending on the relocation type, add the delta as appropriate */
                    if(type == IMAGE_REL_BASED_DIR64){
                        *reinterpret_cast<DWORD64*>(blockPtr + entry->offset) += delta;
                    } else if(type == IMAGE_REL_BASED_HIGHLOW){
                        *reinterpret_cast<DWORD*>(blockPtr + entry->offset) += delta;
                    } else if(type == IMAGE_REL_BASED_HIGH){
                        *reinterpret_cast<WORD*>(blockPtr + entry->offset) += HIWORD(delta);
                    } else if(type == IMAGE_REL_BASED_LOW){
                        *reinterpret_cast<WORD*>(blockPtr + entry->offset) += LOWORD(delta);
                    }

                    entry++;
                }
            }

            relocations = reinterpret_cast<PIMAGE_BASE_RELOCATION>(
                reinterpret_cast<ULONG_PTR>(relocations) + relocations->SizeOfBlock);
        }

        return true;
    }



    inline size_t ComputeDifferenceSmall(
        _In_reads_bytes_(size) char* buf1, 
        _In_reads_bytes_(size) char* buf2, 
        size_t size) {

        /* size should be <= 0x1000 bytes */
        /* In my particular case, I expect frequent differences if any at all are present. */
        size_t res = 0;

        for (size_t i = 0; i < (size & ~0xF); i += 0x8) {
            uint64_t diff1 = *reinterpret_cast<uint64_t*>(buf1) ^ *reinterpret_cast<uint64_t*>(buf2);
            if (!diff1) continue;

            /* Bit fiddle to make each byte 1 if they're different and 0 if the same */
            diff1 = ((diff1 & 0xF0F0F0F0F0F0F0F0ULL) >> 4) | (diff1 & 0x0F0F0F0F0F0F0F0FULL);
            diff1 = ((diff1 & 0x0C0C0C0C0C0C0C0CULL) >> 2) | (diff1 & 0x0303030303030303ULL);
            diff1 = ((diff1 & 0x0202020202020202ULL) >> 1) | (diff1 & 0x0101010101010101ULL);

            /* Sum the bytes */
            diff1 = (diff1 >> 32) + (diff1 & 0xFFFFFFFFULL);
            diff1 = (diff1 >> 16) + (diff1 & 0xFFFFULL);
            diff1 = (diff1 >> 8) + (diff1 & 0xFFULL);
            diff1 = (diff1 >> 4) + (diff1 & 0xFULL);

            res += diff1;
        }

        for (size_t i = (size & ~0xF); i < size; i++) {
            res += (buf1[i] != buf2[i]);
        }

        return res;
    }

    size_t ComputeDifference(_In_ MemoryWrapper<>& m1, _In_ MemoryWrapper<>& m2, _In_ size_t size) {
        auto buf1{ m1.ToAllocationWrapper(size) };
        auto buf2{ m2.ToAllocationWrapper(size) };
        size_t res = 0;

        /* I expect most pages to be identical, and both buffers should be page aligned if larger than a page */
        /* memcmp has more optimizations than I'll ever come up with, so I can just use that to determine if
         * I need to check for differences in the page. */
        for (size_t pn = 0; pn < (size & ~0xFFF); pn += 0x1000) {
            if (memcmp(&buf1[pn], &buf2[pn], 0x1000)) {
                res += ComputeDifferenceSmall(&buf1[pn], &buf2[pn], 0x1000);
            }
        }

        return res + ComputeDifferenceSmall(&buf1[size & ~0xFFF], &buf2[size & ~0xFFF], size & 0xFFF);
    }

    size_t ComputeNonzero(_In_ MemoryWrapper<>& m1, _In_ size_t size) {
        auto buf{ m1.ToAllocationWrapper(size) };
        size_t nonzero{ 0 };
        for (size_t i = 0; i < size; i++) {
            if (buf[i]) {
                nonzero += 1;
            }
        }
        return nonzero;
    }

    ConsistencyData CheckExecutableConsistency(_In_ MemoryWrapper<>& fileBase, _In_ MemoryWrapper<>& memBase,
        _In_ std::vector<MEMORY_BASIC_INFORMATION>& regions){

        auto fileNt = fileBase.GetOffset(fileBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS64>();

        /* We've already confirmed the headers are consistent. */
        size_t diff = 0;
        auto cnt{ fileNt->FileHeader.NumberOfSections };
        auto offset{ fileNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? sizeof(IMAGE_NT_HEADERS64) : 
            sizeof(IMAGE_NT_HEADERS32) };
        auto fileSections = fileNt.GetOffset(offset).Convert<IMAGE_SECTION_HEADER>();

        /* This maps RVAs to the associated PE section header. */
        std::map<DWORD, IMAGE_SECTION_HEADER> rvaConverter{};
        for (auto i = 0; i < cnt; i++) {
            for (auto j = fileSections->VirtualAddress; j < fileSections->VirtualAddress + fileSections->SizeOfRawData;
                j += 0x1000) {

                /* Map the relative virtual address to the associated section header */
                rvaConverter.emplace(j, *fileSections);
            }

            /* Unlike raw pointers, GetOffset always counts bytes, not instances of the pointee type. */
            fileSections = fileSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
        }

        /* For each executable region, go through page by page, find the associated section, and compare */
        for(auto& region : regions){
            if (region.Protect & 0xF0) {
                for (DWORD regPageOffset = 0; regPageOffset < region.RegionSize; regPageOffset += 0x1000) {
                    auto allocOffset{ reinterpret_cast<ULONG_PTR>(region.BaseAddress) - 
                        reinterpret_cast<ULONG_PTR>(region.AllocationBase) + regPageOffset };

                    RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Executable Memory not in a Section"),
                        rvaConverter.find(allocOffset) == rvaConverter.end());
                    auto section{ rvaConverter[allocOffset] };

                    DWORD sectionOffset{ static_cast<DWORD>(allocOffset - section.VirtualAddress) };
                    DWORD inSection{ min(0x1000, section.SizeOfRawData - sectionOffset) };
                    DWORD leftover{ 0x1000 - inSection };

                    diff += ComputeDifference(memBase.GetOffset(allocOffset), 
                        fileBase.GetOffset(section.PointerToRawData + sectionOffset), inSection);
                    diff += ComputeNonzero(memBase.GetOffset(allocOffset + inSection), leftover);
                }
            }
        }

        std::wstring diffString{ std::to_wstring(diff) + L" bytes differ." };
        return diff > 0x500 ? MAKE_CDATA_C(Inconsistent, diffString) : MAKE_CDATA_C(Consistent, diffString);
    }

    ConsistencyData CheckMappedConsistency(_In_ const HandleWrapper& hProcess, _In_ LPVOID lpBaseAddress,
                                           _In_ DWORD dwMapSize){

        /* Get a handle on the memory we're interested in */
        MemoryWrapper<> memBase{ lpBaseAddress, dwMapSize, hProcess };

        auto test{ memBase.ToAllocationWrapper(1) };
        if(!test){
            return MAKE_CDATA_C(Error, L"Unable to read memory");
        }

        /* 
         * We need to find the file mapped to this region. However, if we've been put in a transaction, we can 
         * potentially end up grabbed the transacted version of a file. Since this is the logic underlying process 
         * doppelganging, we need to clear our current transaction before attempting to get the mapped file.
         */
        Linker::RtlSetCurrentTransaction(nullptr);
        auto file{ GetMappedFile(hProcess, lpBaseAddress) };
        if(!file){ 
            /* If the mapped file can't be found, it's likely in a transaction */
            return MAKE_CDATA_C(BadMap, L"Potential Doppelganging");
        }

        if (file->GetFileExists() && !file->HasReadAccess()) {
            return MAKE_CDATA_C(Error, L"Unable to read file");
        }

        if(!IsPEFile(*file)){
            /* If the memory contains a PE but the file does, that's a sign of process herpaderping. */
            /* If the memory isn't a PE, then we shouldn't have anything executing out of it. */
            return IsPEData(memBase) ? MAKE_CDATA_C(BadMap, L"Potential Herpaderping") : MAKE_CDATA(NotPE);
        }

        /* Go through and record the memory protections on the sections in the memory region. */
        std::vector<MEMORY_BASIC_INFORMATION> sections{};
        ULONG_PTR base{ reinterpret_cast<ULONG_PTR>(lpBaseAddress) };
        while(base < reinterpret_cast<ULONG_PTR>(lpBaseAddress) + dwMapSize){
            MEMORY_BASIC_INFORMATION memoryInfo{};
            if(!VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(base), &memoryInfo, sizeof(memoryInfo))){
                return MAKE_CDATA_C(Error, L"Unable to scan memory protections");
            } else{
                sections.emplace_back(memoryInfo);
                base += memoryInfo.RegionSize;
            }
        }

        auto fileContents{ file->Read() };
        if(!fileContents){
            return MAKE_CDATA_C(Error, L"Unable to read backing file");;
        }

        /* Go through the file and memory, and make sure the page protections haven't been changed. */
        MemoryWrapper<> fileBase(fileContents, fileContents.GetSize());
        auto sectionCoherency{ CheckSectionCoherency(fileBase, memBase) };
        if(sectionCoherency != MapConsistency::Consistent){
            return sectionCoherency;
        }

        /* If we're comparing the memory against its file representation, we need to simulate the relocations. */
        if (!SimulateRelocations(fileBase, lpBaseAddress)) {
            std::wcout << L"[WARN] Unable to apply relocations for image at " << lpBaseAddress << L" (" << file->GetFilePath() 
                << L") in PID " << GetProcessId(hProcess) << L". This may result in increased inconsistency." << std::endl;
        }

        /* Make sure the executable sections are consistent with the file now. */
        return CheckExecutableConsistency(fileBase, memBase, sections);
    }

    std::vector<ConsistencyData> CheckProcessMemoryConsistency(_In_ const HandleWrapper& hProcess){
        std::vector<ConsistencyData> consistencies{};

        ULONG_PTR base{ 0 };
        LPVOID regionBase{ nullptr };

        /* Enumerate usermode portion of virtual memory */
        while(base < (1LL << 48)){
            MEMORY_BASIC_INFORMATION memory{};
            if(!VirtualQueryEx(hProcess, reinterpret_cast<LPVOID>(base), &memory, sizeof(memory))){
                /* If there's an error, we're done here */
                return consistencies;
            } else{
                /* 
                 * If we've marked the start of the region about which we are concerned and the base of the current 
                 * allocation isn't that address, it means we're in a new region now. We need to check the previous
                 * region.
                 */
                if(regionBase && memory.AllocationBase != regionBase){
                    /* The size of the previous region is the difference between its start address and this address */
                    auto size = 
                        reinterpret_cast<ULONG_PTR>(memory.BaseAddress) - reinterpret_cast<ULONG_PTR>(regionBase);

                    /* Check the region to ensure it's consistent. */
                    consistencies.emplace_back(CheckMappedConsistency(hProcess, regionBase, size));
                    /* Now that we finished off that region, we're no longer in a region we care about */
                    regionBase = nullptr;
                } 
                
                /* If we're not in a region we already know we care about, need to check if we're in a new image */
                if(memory.AllocationBase != regionBase && memory.Type == MEM_IMAGE){
                    regionBase = memory.AllocationBase;
                }
            }
            base += memory.RegionSize;
        }

        return consistencies;
    }

    std::vector<ConsistencyData> RunConsistencyChecks(void) {
        std::cout << "Checking memory consistency!" << std::endl;

        /* Enumerate the PIDs of all processes on the system. */
        std::vector<DWORD> processes(1024);
        DWORD dwBytesNeeded{};
        auto success{ EnumProcesses(processes.data(), 1024 * sizeof(DWORD), &dwBytesNeeded) };
        if (dwBytesNeeded > 1024 * sizeof(DWORD)) {
            processes.resize(dwBytesNeeded / sizeof(DWORD));
            success = EnumProcesses(processes.data(), dwBytesNeeded, &dwBytesNeeded);
        }

        std::vector<Promise<std::vector<ConsistencyData>>> promises{};
        auto dwProcCount{ dwBytesNeeded / sizeof(DWORD) };
        for (int i = 0; i < dwProcCount; i++) {
            auto proc{ processes[i] };
            HandleWrapper process{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION | PROCESS_VM_OPERATION, false, proc) };
            if (!process) {
                std::wstring img{ GetProcessImage(proc) };
                std::wcout << L"[-] Unable to open PID " << proc;
                if (img.length()) std::wcout << L" (" << img << ")";
                std::wcout << std::endl;
            }

            /* For each process, we want to asynchronously check its memory consistency. */
            promises.emplace_back(ThreadPool::GetInstance().RequestPromise<std::vector<ConsistencyData>>([process]() {
                return CheckProcessMemoryConsistency(process);
                }));
        }

        /* Await each promised result and combine them into the vector */
        std::vector<ConsistencyData> results{};
        for (const auto& promise : promises) {
            auto result{ std::move(promise.GetValue()) };
            if (result) {
                for (auto& consistencyData : *result) {
                    results.emplace_back(consistencyData);
                }
            }
        }

        std::wofstream output{ L".\\DEEPGLASS-Results\\Inconsistent-Images.txt" };
        std::map<std::wstring, std::vector<std::wstring>> found{};
        for(auto& result : results){
            if(MapConsistency::Consistent != result){

                auto end{ reinterpret_cast<LPVOID>(reinterpret_cast<SIZE_T>(result.baseAddress) + result.regionSize) };
                auto image{ GetMappedFile(result.process, result.baseAddress) };
                auto proc{ GetProcessImage(result.process) };

                std::wstringstream procStream{};
                std::wstringstream imgStream{};

                procStream << L"PID " << GetProcessId(result.process);
                if(proc.length()) procStream << L" (" << proc << L")";
                procStream << L" at " << result.baseAddress << L" : " << end;
                auto procString{ procStream.str() };

                if(image){
                    imgStream << image->GetFilePath() << L": ";
                }
                else {
                    imgStream << "Unknown Doppelgang: ";
                }
                if(MapConsistency::BadMap == result) imgStream << L"Bad Map";
                if(MapConsistency::Inconsistent == result) imgStream << L"Inconsistent With File";
                if(MapConsistency::NotPE == result) imgStream << L"Mapped File Not a PE";
                if(MapConsistency::Error == result) imgStream << L"Error";
                if(result.comment){ imgStream << L" - " << *result.comment; }
                auto imgString{ imgStream.str() };

                if (found.find(imgString) == found.end()) {
                    found.emplace(imgString, std::vector<std::wstring>{});
                }
                found.at(imgString).push_back(procString);
            }
        }

        for (auto& pair : found) {
            output << pair.first << std::endl;
            for (auto& proc : pair.second) {
                output << L"\t" << proc << std::endl;
            }
        }

        return results;
    }
}