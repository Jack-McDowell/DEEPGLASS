#pragma once

#include <Windows.h>

#include "DEEPGLASS/Filtering.h"
#include "util/processes/ProcessUtils.h"

DEFINE_FUNCTION(NTSTATUS, RtlSetCurrentTransaction, NTAPI, HANDLE TransactionHandle);

namespace DEEPGLASS{

    /*!
     * \brief Represents the result of an image consistency check
     */
    enum class MapConsistency {
        BadMap,        // The in-memory image is not properly mapped to a file
        NotPE,         // The in-memory image does not meet the PE32+ standard
        Inconsistent,  // The in-memory image is inconsistant with its backing file
        Consistent,    // The in-memory image is consistent with its backing file
        Error          // An error occured while checking the image consistency
    };

    /**
     * \brief Stores the map consistency of a memory region in addition to information about the memory region
     */
    struct ConsistencyData {
        /// The map consistency of the memory region
        MapConsistency consistency;

        /// An optional comment regarding the value of `consistency`
        std::optional<std::wstring> comment{ std::nullopt };

        /// The base address for the memory region
        LPVOID baseAddress{ nullptr };

        /// The size of the region of memory
        SIZE_T regionSize{ 0 };

        /// The process in which the memory region is located
        HANDLE process{ INVALID_HANDLE_VALUE };

        ConsistencyData(_In_ MapConsistency consistency);
        ConsistencyData(_In_ MapConsistency consistency, _In_ const MemoryWrapper<>& regionInfo, 
                        _In_ const std::optional<std::wstring>& comment = std::nullopt);

        operator MapConsistency() const;
        bool operator==(MapConsistency consistency) const;
        bool operator!=(MapConsistency consistency) const;
    };

    /*!
     * \brief Ensures the in-memory sections are coherent with those listed in the file. 
     * 
     * \details For a section to be coherent, it must meet the following requirements:
     *            1. If the memory region is executable, the section header must specify that the section is executable
     *            2. The memory region must be no larger than the section header specifies
     *            3. The in-memory section headers must match the in-file section headers exactly
     * 
     * \param[in] fileBase A memory wrapper pointing to the base of the PE as stored in the file (sections not expanded)
     * \param[in] memBase A memory wrapper pointing to the base of the PE as stored in memory. May be inter-process.
     * \param[in] sections A vector of MEMORY_BASIC_INFORMATION objects for all memory regions the PE occupies.
     * 
     * \return A map consistency enum holding MapConsistency::Consistent if all sections are coherent, or 
     *         MapConsistency::Inconsistent if at least one section is not coherent.
     */
    ConsistencyData CheckSectionCoherency(_In_ MemoryWrapper<>& fileBase, _In_ MemoryWrapper<>& memBase,
                                           _In_ std::vector<MEMORY_BASIC_INFORMATION>& sections);

    /*!
     * \brief Applies relocations to the file representation of the PE in question.
     * 
     * \param fileBase A memory wrapper pointing to the base of the PE as stored in the file (sections not expanded)
     * \param loadBase The address to simulate as the load base address (i.e. the base address of the mapped image)
     * 
     * \return True if successful; false if an error occured. Note that failure in this function does not necessarily
     *         mean that the in-memory image is inconsistent, but all relocations will appear as inconsistencies. 
     */
    bool SimulateRelocations(_In_ MemoryWrapper<>& fileBase, _In_ LPVOID loadBase);

    /*!
     * \brief Compute the number of bytes different between two memory regions
     * 
     * \param m1 The first memory region
     * \param m2 The second memory region
     * \param size The number of bytes to compare
     * 
     * \return The number of bytes different between the two memory regions
     */
    size_t ComputeDifference(_In_ MemoryWrapper<>& m1, _In_ MemoryWrapper<>& m2, _In_ size_t size);

    /*!
     * \brief Checks if all executable sections in a memory-mapped file are consistent with the content in the file.
     * 
     * \note "Consistent" as used here means no more than 0x500 bytes differ from those in the file.
     * 
     * \param fileBase A memory wrapper pointing to the base of the PE as stored in the file (sections not expanded).
     *        Note that SimulateRelocations should be called on fileBase first.
     * \param memBase A memory wrapper pointing to the base of the PE as stored in memory. May be inter-process.
     * 
     * \return A map consistency enum holding MapConsistency::Consistent if all executable sections are consistent, or 
     *         MapConsistency::Inconsistent if at least 0x500 bytes differ.
     */
    ConsistencyData CheckExecutableConsistency(_In_ MemoryWrapper<>& fileBase, _In_ MemoryWrapper<>& memBase);

    /*!
     * \brief Checks if a region in memory is consistent with the file from which it is mapped. Note that this isn't
     *          exhaustive; in particular, this checks that the memory is mapped to a PE file, the page protections
     *        don't violate the constraints set in the file, and that the executable sections match the file.
     * 
     * \param hProcess The process containing the memory region in question
     * \param lpBaseAddress The base address of the memory region in question
     * \param dwMapSize The size of the memory region in question
     * 
     * \return A MapConsistency object containing the result of the checks performed by this function
     */
    ConsistencyData CheckMappedConsistency(_In_ const HandleWrapper& hProcess, _In_ LPVOID lpBaseAddress,
                                           _In_ DWORD dwMapSize);

    /*!
     * \brief Checks all memory in a process for mapped files, and for each one, checks its consistency.
     *        Note that this isn't exhaustive; in particular, this checks that the memory is mapped to a PE file, 
     *        the page protections don't violate the constraints set in the file, and that the executable sections 
     *        match the file.
     * 
     * \param hProcess The process containing the memory region in question
     * 
     * \return A vector of MapConsistency objects containing the result of the consistency checks.
     */
    std::vector<ConsistencyData> CheckProcessMemoryConsistency(_In_ const HandleWrapper& hProcess);

    /*!
     * \brief Checks all memory in all process for mapped files, and for each one, checks its consistency.
     *        Note that this isn't exhaustive; in particular, this checks that the memory is mapped to a PE file, 
     *        the page protections don't violate the constraints set in the file, and that the executable sections 
     *        match the file.
     * 
     * \return A vector of MapConsistency objects containing the result of the consistency checks.
     */
    std::vector<ConsistencyData> RunConsistencyChecks(void);
}