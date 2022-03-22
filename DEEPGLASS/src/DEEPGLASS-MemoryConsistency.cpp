#include "DEEPGLASS/MemoryConsistency.h"

#include <Windows.h>
#include <Psapi.h>

#include "DEEPGLASS/Filtering.h"
#include "util/processes/ProcessUtils.h"
#include "util/Threadpool.h"

#include <iostream>
#include <vector>
#include <fstream>

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

    ConsistencyData CheckSectionCoherency(_In_ MemoryWrapper<>& fileBase, _In_ MemoryWrapper<>& memBase,
                                          _In_ std::vector<MEMORY_BASIC_INFORMATION>& sections){
        /* DOS headers should match exactly. */
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"DOS header mismatch"),
                  !fileBase.CompareMemory(memBase, sizeof(IMAGE_DOS_HEADER)));

        auto fileNt = fileBase.GetOffset(fileBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS>();
        auto memNt = memBase.GetOffset(memBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS>();

        /* Section count, architecture, and data directories should match exactly. */
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Section count mismatch"),
                  fileNt->FileHeader.NumberOfSections != memNt->FileHeader.NumberOfSections);
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Architecture mismatch"),
                  fileNt->FileHeader.Machine != memNt->FileHeader.Machine);
        RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Data directory mismatch"),
                  0 != memcmp(&fileNt->OptionalHeader.DataDirectory, &memNt->OptionalHeader.DataDirectory, 
                              IMAGE_NUMBEROF_DIRECTORY_ENTRIES * sizeof(IMAGE_DATA_DIRECTORY)));

        auto cnt{ memNt->FileHeader.NumberOfSections };
        auto offset{ memNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? sizeof(IMAGE_NT_HEADERS64) :
                                                                             sizeof(IMAGE_NT_HEADERS32) };
        auto fileSections{ fileNt.GetOffset(offset).Convert<IMAGE_SECTION_HEADER>() };
        auto memSections{ memNt.GetOffset(offset).Convert<IMAGE_SECTION_HEADER>() };
        std::vector<std::pair<DWORD, DWORD>> allowedExecutable{};
        for(auto i = 0; i < cnt + 1; i++){
            /* Section headers should be unchanged. */
            RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Section header mismatch"),
                      !fileSections.CompareMemory(memSections, sizeof(IMAGE_SECTION_HEADER)));
            
            /* If the section is executable, record the RVA and size. */
            bool executable{ static_cast<bool>(fileSections->Characteristics & 0x20000000) };
            if(executable){
                /* Round the size up to the nearest page. */
                allowedExecutable.emplace_back(
                    std::make_pair(fileSections->VirtualAddress, (fileSections->SizeOfRawData + 0xFFFUL) & ~0xFFFUL));
            }
            fileSections = fileSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
            memSections = memSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
        }

        /* Compare the section characteristics to the page protections. */
        for(auto& section : sections){
            /* If the pages in the region are exectuable... */
            if(section.Protect & 0xF0){
                auto offset = ULONG_PTR(section.AllocationBase) - ULONG_PTR(memBase.address);
                bool permitted = false;
                /* For each section allowed to be executable, check if this section is that region */
                for(auto& pair : allowedExecutable){
                    permitted = permitted || (pair.first == offset && pair.second >= section.RegionSize);
                }
                RETURN_IF(MAKE_CDATA_C(Inconsistent, L"Section protection mismatch"), !permitted);
            }
        }

        return MAKE_CDATA(Consistent);
    }

    bool SimulateRelocations(_In_ MemoryWrapper<>& fileBase, _In_ LPVOID loadBase){
        auto fileNt{ fileBase.GetOffset(fileBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS64>() };

        IMAGE_DATA_DIRECTORY entry{};
        ULONG_PTR offset{};
        auto delta{ reinterpret_cast<ULONG_PTR>(loadBase) };

        /* We need to support both architectures here, and the optional header varies in size between architectures. */
        if(fileNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64){
            entry = fileNt->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            offset = sizeof(IMAGE_NT_HEADERS64);
            delta -= fileNt->OptionalHeader.ImageBase;
        } else{
            entry = fileNt.Convert<IMAGE_NT_HEADERS32>()->OptionalHeader.DataDirectory[IMAGE_DIRECTORY_ENTRY_BASERELOC];
            offset = sizeof(IMAGE_NT_HEADERS32);
            delta -= fileNt.Convert<IMAGE_NT_HEADERS32>()->OptionalHeader.ImageBase;
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
        auto relocations{ fileBase.GetOffset(offset).Convert<IMAGE_BASE_RELOCATION>() };

        /* relocations will refer to the currently process relocation block. The last will be empty. */
        while(relocations->SizeOfBlock){
            if(rvaConverter.find(relocations->VirtualAddress) != rvaConverter.end()){

                /* 
                 * The virtual address of a relocation block is always a page aligned address, and all relocation
                 * entries therein are comprised of a page offset and a relocation type. Each relocation block
                 * consists of some number of relocation entries as determined by the SizeOfBlock property of the
                 * struct. We need to convert the block pointer (blockPtr) to a raw file offset, but since the
                 * same page is part of the same section and therefore will always have the same difference between
                 * the virtual address and file offset, each individual relocation does not need to be retranslated.
                 */
                auto blockPtr{ fileBase.GetOffset(RVA_TO_RAW(relocations->VirtualAddress)) };

                /* SizeOfBlock refers to the number of bytes in the block. Exclude the struct itself. */
                auto cnt{ (relocations->SizeOfBlock - sizeof(IMAGE_BASE_RELOCATION)) / sizeof(RELOC_ENTRY) };
                auto entry{ relocations.GetOffset(sizeof(IMAGE_BASE_RELOCATION)).Convert<RELOC_ENTRY>() };

                for(auto i{ 0ul }; i < cnt; i++){
                    auto type{ entry->type };

                    /* Depending on the relocation type, add the delta as appropriate */
                    if(type == IMAGE_REL_BASED_DIR64){
                        blockPtr.GetOffset(entry->offset).Convert<ULONG_PTR>().SetValue(
                            *blockPtr.GetOffset(entry->offset).Convert<ULONG_PTR>() + delta);
                    } else if(type == IMAGE_REL_BASED_HIGHLOW)
                        blockPtr.GetOffset(entry->offset).Convert<DWORD>().SetValue(
                            *blockPtr.GetOffset(entry->offset).Convert<DWORD>() + static_cast<DWORD>(delta));
                    else if(type == IMAGE_REL_BASED_HIGH)
                        blockPtr.GetOffset(entry->offset).Convert<WORD>().SetValue(
                            *blockPtr.GetOffset(entry->offset).Convert<WORD>() + HIWORD(delta));
                    else if(type == IMAGE_REL_BASED_LOW)
                        blockPtr.GetOffset(entry->offset).Convert<WORD>().SetValue(
                            *blockPtr.GetOffset(entry->offset).Convert<WORD>() + LOWORD(delta));

                    entry = entry.GetOffset(sizeof(RELOC_ENTRY));
                }
            }

            relocations = relocations.GetOffset(relocations->SizeOfBlock);
        }

        return true;
    }

    size_t ComputeDifference(_In_ MemoryWrapper<>& m1, _In_ MemoryWrapper<>& m2, _In_ size_t size){
        return size - RtlCompareMemory(m1.ToAllocationWrapper(), m2.ToAllocationWrapper(), size);
    }

    ConsistencyData CheckExecutableConsistency(_In_ MemoryWrapper<>& fileBase, _In_ MemoryWrapper<>& memBase){
        auto fileNt = fileBase.GetOffset(fileBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS>();
        auto memNt = memBase.GetOffset(memBase.Convert<IMAGE_DOS_HEADER>()->e_lfanew).Convert<IMAGE_NT_HEADERS>();

        /* We've already confirmed the headers are consistent. */
        size_t diff = 0;
        auto cnt{ memNt->FileHeader.NumberOfSections };
        auto offset{ fileNt->FileHeader.Machine == IMAGE_FILE_MACHINE_AMD64 ? sizeof(IMAGE_NT_HEADERS64) : 
            sizeof(IMAGE_NT_HEADERS32) };
        auto fileSections = fileNt.GetOffset(offset).Convert<IMAGE_SECTION_HEADER>();
        auto memSections = memNt.GetOffset(offset).Convert<IMAGE_SECTION_HEADER>();

        /* For each section, if it's executable, find the difference in bytes */
        for(auto i = 0; i < cnt; i++){
            if(fileSections->Characteristics & 0x2000000){
                /*
                 * We're making a potentially flawed design choice here; we're comparing the sections up to their
                 * SizeOfRawData, which is the number of bytes actually in the section. This almost never is as big as 
                 * the memory region in which the section has been mapped since the memory region is always rounded up
                 * to the next page (and this size is the SizeOfRawData). Thus, it's possible that something could be 
                 * mapped in the 0x1000 - (SizeOfRawData & 0xFFF) leftover bytes... but technically the contents of 
                 * that memory is undefined. Perhaps it's worth making sure that it's all zeroes, as the implementation
                 * of section mapping currently does. A job for another time, I suppose.
                 */
                diff += ComputeDifference(fileBase.GetOffset(fileSections->PointerToRawData),
                                          memBase.GetOffset(memSections->VirtualAddress), 
                                          fileSections->SizeOfRawData);
            }
            fileSections = fileSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
            memSections = memSections.GetOffset(sizeof(IMAGE_SECTION_HEADER));
        }

        std::wstring diffString{ std::to_wstring(diff) + L" bytes differ." };
        return diff > 0x500 ? MAKE_CDATA_C(Inconsistent, diffString) : MAKE_CDATA_C(Consistent, diffString);
    }

    ConsistencyData CheckMappedConsistency(_In_ const HandleWrapper& hProcess, _In_ LPVOID lpBaseAddress,
                                           _In_ DWORD dwMapSize){

        /* Get a handle on the memory we're interested in */
        MemoryWrapper<> memBase{ lpBaseAddress, dwMapSize, hProcess };

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
        auto sectionCoherency{ CheckSectionCoherency(fileBase, memBase, sections) };
        if(sectionCoherency != MapConsistency::Consistent){
            return sectionCoherency;
        }

        /* If we're comparing the memory against its file representation, we need to simulate the relocations. */
        if(!SimulateRelocations(fileBase, lpBaseAddress)){
            std::wcout << L"[WARN] Unable to apply relocations for image at " << lpBaseAddress << L" (" << file->GetFilePath() 
                << L") in PID " << GetProcessId(hProcess) << L". This may result in increased inconsistency." << std::endl;
        }

        /* Make sure the executable sections are consistent with the file now. */
        return CheckExecutableConsistency(fileBase, memBase);
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

    std::vector<ConsistencyData> RunConsistencyChecks(void){
        std::cout << "Checking memory consistency!" << std::endl;

        /* Enumerate the PIDs of all processes on the system. */
        std::vector<DWORD> processes(1024);
        DWORD dwBytesNeeded{};
        auto success{ EnumProcesses(processes.data(), 1024 * sizeof(DWORD), &dwBytesNeeded) };
        if(dwBytesNeeded > 1024 * sizeof(DWORD)){
            processes.resize(dwBytesNeeded / sizeof(DWORD));
            success = EnumProcesses(processes.data(), dwBytesNeeded, &dwBytesNeeded);
        }

        std::vector<Promise<std::vector<ConsistencyData>>> promises{};
        auto dwProcCount{ dwBytesNeeded / sizeof(DWORD) };
        for(int i = 0; i < dwProcCount; i++){
            auto proc{ processes[i] };
            HandleWrapper process{ OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, false, proc) };
            if(!process){
                std::wstring img{ GetProcessImage(proc) };
                std::wcout << L"[-] Unable to open PID " << proc;
                if(img.length()) std::wcout << L" (" << img << ")";
                std::wcout << std::endl;
            }

            /* For each process, we want to asynchronously check its memory consistency. */
            promises.emplace_back(ThreadPool::GetInstance().RequestPromise<std::vector<ConsistencyData>>([process](){
                return CheckProcessMemoryConsistency(process);
            }));
        }

        /* Await each promised result and combine them into the vector */
        std::vector<ConsistencyData> results{};
        for(const auto& promise : promises){
            auto result{ std::move(promise.GetValue()) };
            if(result){
                for(auto& consistencyData : *result){
                    results.emplace_back(consistencyData);
                }
            }
        }

        std::wofstream output{ L".\\DEEPGLASS-Results\\Inconsistent-Images.txt" };
        for(auto& result : results){
            if(MapConsistency::Consistent != result){
                auto end{ reinterpret_cast<LPVOID>(reinterpret_cast<SIZE_T>(result.baseAddress) + result.regionSize) };
                auto image{ GetMappedFile(result.process, result.baseAddress) };
                auto proc{ GetProcessImage(result.process) };

                output << L"PID " << GetProcessId(result.process);
                if(proc.length()) output << L" (" << proc << L")";
                output << L": Image at " << result.baseAddress << L" : " << end << L" ";
                if(image){
                    output << L"(" << image->GetFilePath() << L") ";
                }
                if(MapConsistency::BadMap == result) output << L"Bad Map";
                if(MapConsistency::Inconsistent == result) output << L"Inconsistent With File";
                if(MapConsistency::NotPE == result) output << L"Mapped File Not a PE";
                if(MapConsistency::Error == result) output << L"Error";
                if(result.comment){ output << L" - " << *result.comment; }
                output << std::endl;
            }
        }

        return results;
    }
}