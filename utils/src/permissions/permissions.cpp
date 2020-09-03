#include "util/permissions/permissions.h"
#include "util/log/Log.h"

namespace Permissions{

	bool AccessIncludesAll(const ACCESS_MASK& access){
		return ((access & GENERIC_ALL) == GENERIC_ALL) ||
			((access & FILE_ALL_ACCESS) == FILE_ALL_ACCESS);
	}

	bool AccessIncludesWrite(const ACCESS_MASK& access){
		return AccessIncludesAll(access) ||
			((access & GENERIC_WRITE) == GENERIC_WRITE) ||
			((access & FILE_GENERIC_WRITE) == FILE_GENERIC_WRITE);
	}

	bool AccessIncludesRead(const ACCESS_MASK& access){
		return AccessIncludesAll(access) ||
			((access & GENERIC_READ) == GENERIC_READ) ||
			((access & FILE_GENERIC_READ) == FILE_GENERIC_READ);
	}

	bool AccessIncludesExecute(const ACCESS_MASK& access){
		return AccessIncludesAll(access) ||
			((access & GENERIC_EXECUTE) == GENERIC_EXECUTE) ||
			((access & FILE_GENERIC_EXECUTE) == FILE_GENERIC_EXECUTE);
	}

	bool AccessIncludesWriteOwner(const ACCESS_MASK& access){
		return AccessIncludesAll(access) ||
			((access & WRITE_OWNER) == WRITE_OWNER);
	}

	bool AccessContainsDelete(const ACCESS_MASK& access){
		return AccessIncludesAll(access) ||
			((access & DELETE) == DELETE);
	}

	void AccessAddAll(ACCESS_MASK& access){
		access |= GENERIC_ALL;
	}

	void AccessAddWrite(ACCESS_MASK& access){
		access |= GENERIC_WRITE;
	}

	void AccessAddRead(ACCESS_MASK& access){
		access |= GENERIC_READ;
	}

	void AccessAddExecute(ACCESS_MASK& access){
		access |= GENERIC_EXECUTE;
	}

	void AccessAddWriteOwner(ACCESS_MASK& access){
		access |= WRITE_OWNER;
	}

	void AccessAddDelete(ACCESS_MASK& access){
		access |= DELETE;
	}

	ACCESS_MASK GetOwnerRightsFromACL(const Owner& owner, const SecurityDescriptor& acl){
		TRUSTEE_W tOwnerTrustee;
		BuildTrusteeWithSidW(&tOwnerTrustee, owner.GetSID());
		ACCESS_MASK amAccess{ 0 };
		auto dacl = acl.GetDACL();
		auto x{ GetLastError() };
		HRESULT hr = GetEffectiveRightsFromAclW(dacl, &tOwnerTrustee, &amAccess);
		if(hr != ERROR_SUCCESS){
			LOG_ERROR("Error getting rights from acl with owner " << owner << ". ERROR: " << hr);
			return 0;
		}
		return amAccess;
	}

	bool UpdateObjectACL(const std::wstring& wsObjectName, const SE_OBJECT_TYPE& seObjectType, const Owner& oOwner, const ACCESS_MASK& amDesiredAccess, const bool& bDeny){
		PACL pOldDacl;
		PSECURITY_DESCRIPTOR pDesc{ nullptr };
		HRESULT hr = GetNamedSecurityInfoW(reinterpret_cast<LPCWSTR>(wsObjectName.c_str()), seObjectType, DACL_SECURITY_INFORMATION, nullptr, nullptr, &pOldDacl, nullptr, &pDesc);
		AllocationWrapper awDesc{ pDesc, 0, AllocationWrapper::LOCAL_ALLOC };
		if(hr != ERROR_SUCCESS){
			LOG_ERROR("Couldn't read current DACL for object " << wsObjectName << ". (Error " << hr << ")");
			SetLastError(hr);
			return false;
		}
		ACCESS_MODE amAccessMode = bDeny ? DENY_ACCESS : GRANT_ACCESS;
		EXPLICIT_ACCESS ea;
		ZeroMemory(&ea, sizeof(EXPLICIT_ACCESS));
		ea.grfAccessPermissions = amDesiredAccess;
		ea.grfAccessMode = amAccessMode;
		ea.grfInheritance = OBJECT_INHERIT_ACE | CONTAINER_INHERIT_ACE;
		BuildTrusteeWithSidW(&ea.Trustee, oOwner.GetSID());

		PACL pNewDacl{ nullptr };
		hr = SetEntriesInAcl(1, &ea, pOldDacl, &pNewDacl);
		AllocationWrapper awNewDacl{ pNewDacl, 0, AllocationWrapper::LOCAL_ALLOC };
		if(hr != ERROR_SUCCESS){
			LOG_ERROR("Couldn't update DACL for object " << wsObjectName << ". (Error " << hr << ")");
			SetLastError(hr);
			return false;
		}

		hr = SetNamedSecurityInfoW(const_cast<LPWSTR>(wsObjectName.c_str()), seObjectType,
								   DACL_SECURITY_INFORMATION,
								   NULL, NULL, pNewDacl, NULL);
		if(hr != ERROR_SUCCESS){
			LOG_ERROR("Couldn't set new DACL for object " << wsObjectName << ". (Error " << hr << ")");
			SetLastError(hr);
			return false;
		}
		return true;
	}


	SecurityDescriptor::SecurityDescriptor(DWORD dwSize, SecurityDescriptor::SecurityDataType type) :
		GenericWrapper<PISECURITY_DESCRIPTOR>(reinterpret_cast<PISECURITY_DESCRIPTOR>(HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, dwSize)),
											  [](LPVOID memory){ HeapFree(GetProcessHeap(), 0, memory); }, nullptr){
		switch(type){
		case SecurityDescriptor::SecurityDataType::USER_SID:
			lpUserSID = reinterpret_cast<PSID>(*ReferenceCounter);
			break;
		case SecurityDescriptor::SecurityDataType::GROUP_SID:
			lpGroupSID = reinterpret_cast<PSID>(*ReferenceCounter);
			break;
		case SecurityDescriptor::SecurityDataType::DACL:
			dacl = reinterpret_cast<PACL>(*ReferenceCounter);
			break;
		case SecurityDescriptor::SecurityDataType::SACL:
			sacl = reinterpret_cast<PACL>(*ReferenceCounter);
			break;
		}
	}

	SecurityDescriptor::SecurityDescriptor(PISECURITY_DESCRIPTOR lpSecurity) :
		GenericWrapper<PISECURITY_DESCRIPTOR>(lpSecurity, LocalFree, nullptr){
		if(lpSecurity){
			lpUserSID = lpSecurity->Owner;
			lpGroupSID = lpSecurity->Group;
			dacl = lpSecurity->Dacl;
			sacl = lpSecurity->Sacl;
		}
	}

	SecurityDescriptor SecurityDescriptor::CreateUserSID(DWORD dwSize){
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::USER_SID);
	}

	SecurityDescriptor SecurityDescriptor::CreateGroupSID(DWORD dwSize){
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::GROUP_SID);
	}

	SecurityDescriptor SecurityDescriptor::CreateDACL(DWORD dwSize){
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::DACL);
	}

	SecurityDescriptor SecurityDescriptor::CreateSACL(DWORD dwSize){
		return SecurityDescriptor(dwSize, SecurityDescriptor::SecurityDataType::SACL);
	}

	PACL SecurityDescriptor::GetDACL() const{ return this->dacl; }
	PACL SecurityDescriptor::GetSACL() const{ return this->sacl; }
	PSID SecurityDescriptor::GetUserSID() const{ return this->lpUserSID; }
	PSID SecurityDescriptor::GetGroupSID() const{ return this->lpGroupSID; }

	Owner::Owner(IN const std::wstring& name) : wName{ name }, bExists{ true } {
		DWORD dwSIDLen{};
		DWORD dwDomainLen{};
		SID_NAME_USE SIDType{};
		LookupAccountNameW(nullptr, wName.c_str(), nullptr, &dwSIDLen, nullptr, &dwDomainLen, &SIDType);
		SecurityDescriptor tempSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(dwDomainLen);
		DWORD dwTempDomainLen = dwDomainLen;
		DWORD dwTempSIDLen = dwSIDLen;
		LookupAccountNameW(nullptr, wName.c_str(), tempSID.GetUserSID(), &dwTempSIDLen, Domain.data(), &dwTempDomainLen, &SIDType);

		if(SIDType == SidTypeUser || SIDType == SidTypeDeletedAccount){
			otType = OwnerType::USER;
			LOG_VERBOSE(3, "Owner with name " << wName << " is a user.");
			sdSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
			if(!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetUserSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)){
				LOG_ERROR("Error getting user with name " << wName << " " << GetLastError());
				bExists = false;
			} else{
				wDomainName = std::wstring(Domain.data());
				if(SIDType == SidTypeDeletedAccount){
					LOG_VERBOSE(2, "User with name " << wName << " has been deleted.");
					bExists = false;
				} else if(SIDType != SidTypeUser){
					LOG_VERBOSE(2, "User with name " << wName << " does not exist.");
					bExists = false;
				} else{
					LOG_VERBOSE(3, "User with name " << wName << " found.");
				}
			}
		} else if(SIDType == SidTypeGroup || SIDType == SidTypeWellKnownGroup || SIDType == SidTypeAlias){
			otType = OwnerType::GROUP;
			if(SIDType == SidTypeWellKnownGroup){
				LOG_VERBOSE(3, "Owner with name " << wName << " is a well known group.");
			} else{
				LOG_VERBOSE(3, "Owner with name " << wName << " is a group.");
			}
			sdSID = SecurityDescriptor::CreateGroupSID(dwSIDLen);
			if(!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetGroupSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)){
				LOG_ERROR("Error getting group with name " << wName << " " << GetLastError());
				bExists = false;
			} else{
				wDomainName = std::wstring(Domain.data());
				LOG_VERBOSE(3, "Group with name " << wName << " exists.");
			}
		} else{
			otType = OwnerType::NONE;
			LOG_ERROR("Name " << wName << " does not correspond to a known owner type.");
			bExists = false;
		}
	}

	Owner::Owner(IN const SecurityDescriptor& sid) : sdSID{ sid }, bExists{ true } {
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };
		LookupAccountSidW(nullptr, sdSID.GetUserSID(), nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);

		if(!LookupAccountSid(nullptr, sdSID.GetUserSID(), Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)){
			LOG_ERROR("Error getting owner " << GetLastError());
			bExists = false;
		} else{
			wDomainName = std::wstring(Domain.data());
			wName = std::wstring(Name.data());
			if(SIDType == SidTypeDeletedAccount){
				otType = OwnerType::USER;
				LOG_VERBOSE(2, "User " << wName << " has been deleted.");
				bExists = false;
			} else if(SIDType == SidTypeGroup || SIDType == SidTypeWellKnownGroup || SIDType == SidTypeAlias){
				LOG_VERBOSE(2, "Group " << wName << " exists.");
				otType = OwnerType::GROUP;
			} else if(SIDType == SidTypeUser){
				LOG_VERBOSE(3, "User " << wName << " Exists.");
				otType = OwnerType::USER;
			} else{
				otType = OwnerType::NONE;
				LOG_ERROR("Unknown owner type.");
				bExists = false;
			}
		}
	}

	Owner::Owner(IN const std::wstring& name, IN const bool& exists, IN const OwnerType& type) : wName{ name }, bExists{ exists }, otType{ type } {}

	Owner::Owner(IN const SecurityDescriptor& sid, IN const bool& exists, IN const OwnerType& type) : sdSID{ sid }, bExists{ exists }, otType{ type } {}

	Owner::Owner(IN const std::wstring& name, IN const std::wstring& domain, IN const SecurityDescriptor& sid, IN const bool& exists, IN const OwnerType& type) :
		wName{ name }, wDomainName{ domain }, sdSID{ sid }, bExists{ exists }, otType{ type } {}

	bool Owner::Exists() const{
		return bExists;
	}

	std::wstring Owner::GetName() const{
		return wName;
	}

	std::wstring Owner::GetDomainName() const{
		return wDomainName;
	}

	PSID Owner::GetSID() const{
		if(otType == OwnerType::USER) return sdSID.GetUserSID();
		return sdSID.GetGroupSID();
	}

	OwnerType Owner::GetOwnerType() const{
		return otType;
	}

	std::wstring Owner::ToString() const{
		return wName;
	}

	User::User(IN const std::wstring& uName) : Owner{ uName , true, OwnerType::USER }{
		DWORD dwSIDLen{};
		DWORD dwDomainLen{};
		SID_NAME_USE SIDType{};
		LookupAccountNameW(nullptr, wName.c_str(), nullptr, &dwSIDLen, nullptr, &dwDomainLen, &SIDType);

		sdSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(dwDomainLen);
		if(!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetUserSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)){
			LOG_ERROR("Error getting user with name " << wName << " " << GetLastError());
			bExists = false;
		} else{
			wDomainName = std::wstring(Domain.data());
			if(SIDType == SidTypeDeletedAccount){
				LOG_VERBOSE(2, "User with name " << wName << " has been deleted.");
				bExists = false;
			} else if(SIDType != SidTypeUser){
				LOG_VERBOSE(2, "User with name " << wName << " does not exist.");
				bExists = false;
			} else{
				LOG_VERBOSE(3, "User with name " << wName << " found.");
			}
		}
	}

	User::User(IN const SecurityDescriptor& sid) : Owner{ sid , true, OwnerType::USER }{
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };
		LookupAccountSidW(nullptr, sdSID.GetUserSID(), nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);

		if(!LookupAccountSid(nullptr, sdSID.GetUserSID(), Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)){
			LOG_ERROR("Error getting user " << GetLastError());
			bExists = false;
		} else{
			wDomainName = std::wstring(Domain.data());
			wName = std::wstring(Name.data());
			if(SIDType == SidTypeDeletedAccount){
				LOG_VERBOSE(2, "User " << wName << " has been deleted.");
				bExists = false;
			} else if(SIDType != SidTypeUser){
				LOG_VERBOSE(2, "User doesn't exist.");
				bExists = false;
			} else{
				LOG_VERBOSE(3, "User " << wName << " Exists.");
			}
		}
	}

	Group::Group(IN const std::wstring& name) : Owner{ name, true, OwnerType::GROUP }{
		DWORD dwSIDLen{};
		DWORD dwDomainLen{};
		SID_NAME_USE SIDType{};
		LookupAccountNameW(nullptr, wName.c_str(), nullptr, &dwSIDLen, nullptr, &dwDomainLen, &SIDType);

		sdSID = SecurityDescriptor::CreateUserSID(dwSIDLen);
		std::vector<WCHAR> Domain(dwDomainLen);
		if(!LookupAccountNameW(nullptr, wName.c_str(), sdSID.GetUserSID(), &dwSIDLen, Domain.data(), &dwDomainLen, &SIDType)){
			LOG_ERROR("Error getting user with name " << wName << " " << GetLastError());
			bExists = false;
		} else{
			wDomainName = std::wstring(Domain.data());
			if(SIDType == SidTypeWellKnownGroup){
				LOG_VERBOSE(2, "Group with name " << wName << " is a well known group.");
			} else if(SIDType == SidTypeGroup || SIDType == SidTypeAlias){
				LOG_VERBOSE(2, "Group with name " << wName << " found.");
			} else{
				LOG_VERBOSE(3, "Group with name " << wName << " does not exist.");
				bExists = false;
			}
		}
	}

	Group::Group(IN const SecurityDescriptor& sid) : Owner{ sid, true, OwnerType::GROUP }{
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };
		LookupAccountSidW(nullptr, sdSID.GetUserSID(), nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);

		if(!LookupAccountSid(nullptr, sdSID.GetUserSID(), Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)){
			LOG_ERROR("Error getting user " << GetLastError());
			bExists = false;
		} else{
			wDomainName = std::wstring(Domain.data());
			wName = std::wstring(Name.data());
			if(SIDType == SidTypeWellKnownGroup){
				LOG_VERBOSE(2, "Group with name " << wName << " is a well known group.");
			} else if(SIDType == SidTypeGroup || SIDType == SidTypeAlias){
				LOG_VERBOSE(2, "Group with name " << wName << " found.");
			} else{
				LOG_VERBOSE(3, "Group with name " << wName << " does not exist.");
				bExists = false;
			}
		}
	}

	std::optional<Owner> GetProcessOwner(){
		HANDLE hToken;
		if(!OpenProcessToken(GetCurrentProcess(), TOKEN_QUERY, &hToken)){
			LOG_ERROR("Couldn't access process token. Error " << GetLastError());
			return std::nullopt;
		}
		DWORD dwSize{ 0 };
		GetTokenInformation(hToken, TokenOwner, nullptr, dwSize, &dwSize);
		PTOKEN_OWNER owner = (PTOKEN_OWNER) GlobalAlloc(GPTR, dwSize);
		DWORD dwDomainLen{};
		DWORD dwNameLen{};
		SID_NAME_USE SIDType{ SidTypeUnknown };

		std::vector<WCHAR> Domain(dwDomainLen);
		std::vector<WCHAR> Name(dwNameLen);
		if(owner == nullptr){
			LOG_ERROR("Unable to allocate space for owner token.");
			goto fail;
		}
		if(!GetTokenInformation(hToken, TokenOwner, owner, dwSize, &dwSize)){
			LOG_ERROR("Couldn't get owner from token. Error " << GetLastError());
			goto fail;
		}
		LookupAccountSidW(nullptr, owner->Owner, nullptr, &dwNameLen, nullptr, &dwDomainLen, &SIDType);
		Domain = std::vector<WCHAR>(dwDomainLen);
		Name = std::vector<WCHAR>(dwNameLen);

		if(!LookupAccountSid(nullptr, owner->Owner, Name.data(), &dwNameLen, Domain.data(), &dwDomainLen, &SIDType)){
			LOG_ERROR("Error getting owner " << GetLastError());
		}
		if(owner != nullptr) GlobalFree(owner);
		CloseHandle(hToken);
		return Owner(Name.data());
	fail:
		if(owner != nullptr) GlobalFree(owner);
		CloseHandle(hToken);
		return std::nullopt;
	}
}