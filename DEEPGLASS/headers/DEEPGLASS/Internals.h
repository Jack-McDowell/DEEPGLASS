#pragma once

#include <windows.h>
#include <winternl.h>

#include "util/DynamicLinker.h"

// Define the value to use with NtQuerySystemInformation to get system handle information
#define SystemHandleInformation static_cast<SYSTEM_INFORMATION_CLASS>(0x10)

// Information about a single handle returned by NtQuerySystemInformation
struct HANDLE_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
};

// Information about all system handles returned by NtQuerySystemInformation
struct SYSTEM_HANDLE_INFORMATION {
	ULONG HandleCount;
	HANDLE_INFO Handles[1];
};

#define ObjectNameInformation static_cast<OBJECT_INFORMATION_CLASS>(1)

typedef struct _OBJECT_NAME_INFORMATION {
	UNICODE_STRING Name;
} OBJECT_NAME_INFORMATION, * POBJECT_NAME_INFORMATION;

// Link to NtQuerySystemInformation in NTDLL
DEFINE_FUNCTION(NTSTATUS, NtQuerySystemInformation, NTAPI,
				_In_ SYSTEM_INFORMATION_CLASS SystemInformationClass,
				_Out_writes_bytes_opt_(SystemInformationLength) PVOID SystemInformation,
				_In_ ULONG SystemInformationLength,
				_Out_opt_ ULONG* ReturnLength);

// Link to NtQueryObject in NTDLL
DEFINE_FUNCTION(NTSTATUS, NtQueryObject, NTAPI,
				_In_opt_ HANDLE Handle,
				_In_ OBJECT_INFORMATION_CLASS ObjectInformationClass,
				_Out_writes_bytes_opt_(ObjectInformationLength) PVOID ObjectInformation,
				_In_ ULONG ObjectInformationLength,
				_Out_opt_ PULONG ReturnLength);

namespace DEEPGLASS::Internals {

	/*!
	 * \brief Information to be used by the thread to be used to read the name of handles returned by 
	 *        NtQuerySystemInformation, referred to as the handle reader thread
	 */
	struct ThreadInfo {

		/// \brief The handle that the thread should query
		HANDLE handle;

		/// \brief The path of the object referenced by the handle
		std::vector<char> buf;
	};

	/// \brief An event to be set to run the handle reader thread
	extern HandleWrapper hEvent1;

	/// \brief An event to be set by the handle reader thread to indicate it is finished. If not triggered
	///        within 250 ms of hEvent1 being set, the handle reader thread will be killed.
	extern HandleWrapper hEvent2;

	/// \brief A pointer to the ThreadInfo struct to be used by the handle reader thread
	extern ThreadInfo* info;

	/// \brief A handle to the handle reader thread
	extern HANDLE hThread;

	/*!
	 * \brief Queries the name of the handle pointed to by info's handle, storing the result in info's buf.
	 *        hEvent1 should be triggered for this function to run, and if hEvent2 is not triggered within
	 *        250 ms, the thread running this function should be killed. This function should only be used by
	 *        GetHandleName.
	 */
	void QueryName();

	/*!
	 * \brief Reads the name of a handle in a specified process, returning the name if present. This function is
	 *        only meant to read the name of a handle to a file.
	 * 
	 * \details Reads the name of a specified handle in a specified process by making use of QueryName. Since QueryName
	 *          uses global resources, GetHandleName should not be called asynchronously with other threads also 
	 *          calling GetHandleName or QueryName. This function will not configure hEvent1 or hEvent2 prior to using
	 *          them, so it is the developer's responsibility to ensure they are valid events.
	 * 
	 * \param[in] handle The handle value in the specified process, which may be different than the value of the handle
	 *                   when duplicated to this process.
	 * \param[in] dwPID  The PID of the process which has the handle in question
	 * 
	 * \return The name of the object referenced by the handle, if available; nullopt otherwise.
	 */
	std::optional<std::wstring> GetHandleName(_In_ HANDLE handle, _In_ DWORD dwPID);
}