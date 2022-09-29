// File Example1Server.cpp
#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>
#include <Windows.h>
#include "Aclapi.h"

#include "bsit1_h.h"

#pragma comment(lib, "Rpcrt4.lib")
#pragma comment(lib, "netapi32.lib")
#include <lm.h>
#include <sddl.h>

using namespace std;

HCRYPTPROV hProv;
HCRYPTPROV hProvPair;

HCRYPTKEY hSessionKey;

void getSessionKey(DWORD pCount,  BYTE* pKey,  DWORD* countSession, BYTE** cryptedSessionKey)
{
	//Теперь надо сделать сессионный
	CryptGenKey(hProv, CALG_AES_256, 0x01000000 | CRYPT_EXPORTABLE, &hSessionKey);
	DWORD count = 0;
	BYTE* data;
	int f3 = CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &count);
	data = (BYTE*)malloc(count * sizeof(BYTE));
	int f4 = CryptExportKey(hSessionKey, 0, PLAINTEXTKEYBLOB, 0, data, &count);
	HCRYPTKEY publicKey;
	//Достали публичный ключ
	int f6 = CryptImportKey(hProvPair, pKey, pCount, NULL, NULL, &publicKey);
	DWORD enc = 0;
	int f7 = CryptEncrypt(publicKey, NULL, TRUE, NULL, NULL, &enc, count);
	data = (BYTE*)realloc(data, enc * sizeof(BYTE));
	int f8 = CryptEncrypt(publicKey, NULL, TRUE, NULL, data, &count, enc);

	*cryptedSessionKey = new BYTE[enc];
	memcpy(*cryptedSessionKey, data, enc);
	*countSession = enc;
}

void getOsVersion(DWORD *bufSize, BYTE **buffer)
{
	NET_API_STATUS nStatus;
	DWORD dwLevel = 101;
	LPSERVER_INFO_101 pBuf = NULL;
	LPWSTR pszServerName = NULL;
	nStatus = NetServerGetInfo(pszServerName, dwLevel, (LPBYTE*)&pBuf);
	int major = pBuf->sv101_version_major;
	int minor = pBuf->sv101_version_minor;

	const char* osVersion;

	if (major == 4 && minor == 0)
		osVersion = "Windows 95";
	else if (major == 4 && minor == 10)
		osVersion = "Windows 98";
	else if (major == 4 && minor == 90)
		osVersion = "WindowsMe";
	else if (major == 5 && minor == 0)
		osVersion = "Windows 2000";
	else if (major == 5 && minor == 1)
		osVersion = "Windows XP";
	else if (major == 5 && minor == 2)
		osVersion = "Windows 2003";
	else if (major == 6 && minor == 0)
		osVersion = "Windowx Vista";
	else if (major == 6 && minor == 1)
		osVersion = "Windows 7";
	else if (major == 6 && minor == 2)
		osVersion = "Windows 8";
	else if (major == 6 && minor == 3)
		osVersion = "Windows 8.1";
	else if (major == 10 && minor == 0)
		osVersion = "Windows 10";
	else osVersion = "ERROR";

	DWORD count = strlen(osVersion) + 1;
	BYTE* buf = new BYTE[count];

	memcpy(buf, osVersion, count);

	DWORD crypt_count = count;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &count, crypt_count);
	count = crypt_count;
	*buffer = new BYTE[count];
	memcpy(*buffer, buf, count);
	*bufSize = count;
}

void getCurrentTime(DWORD *bufSize, BYTE **buffer)
{
	SYSTEMTIME sm;
	GetSystemTime(&sm);

	DWORD hour = (sm.wHour + 3) % 24;
	DWORD minute = sm.wMinute;
	DWORD second = sm.wSecond;
	DWORD day = sm.wDay;
	DWORD month = sm.wMonth;
	DWORD year = sm.wYear;

	DWORD count = sizeof(DWORD) * 6;
	BYTE *buf = new BYTE[count];

	memcpy(buf, (const char*)&hour, sizeof(DWORD));
	memcpy(buf + 4, (const char*)&minute, sizeof(DWORD));
	memcpy(buf + 8, (const char*)&second, sizeof(DWORD));
	memcpy(buf + 12, (const char*)&day, sizeof(DWORD));
	memcpy(buf + 16, (const char*)&month, sizeof(DWORD));
	memcpy(buf + 20, (const char*)&year, sizeof(DWORD));

	DWORD crypt_count = count;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &count, crypt_count);
	count = crypt_count;
	*buffer = new BYTE[count];
	memcpy(*buffer, buf, count);
	*bufSize = count;
}

void getTimeFromBootOS(DWORD *bufSize, BYTE **buffer)
{
	unsigned int hour, min, sec;
	unsigned int msec = GetTickCount();
	hour = msec / (1000 * 60 * 60);
	min = msec / (1000 * 60) - hour * 60;
	sec = (msec / 1000) - (hour * 60 * 60) - min * 60;

	DWORD count = sizeof(unsigned int) * 3;
	BYTE *buf = new BYTE[count];

	memcpy(buf, (const char*)&hour, sizeof(unsigned int));
	memcpy(buf + 4, (const char*)&min, sizeof(unsigned int));
	memcpy(buf + 8, (const char*)&sec, sizeof(unsigned int));

	DWORD crypt_count = count;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &count, crypt_count);
	count = crypt_count;
	*buffer = new BYTE[count];
	memcpy(*buffer, buf, count);
	*bufSize = count;
}

void getMemoryStatus(DWORD* bufSize, BYTE** buffer)
{
	MEMORYSTATUS stat;
	GlobalMemoryStatus(&stat);
	DWORD count = sizeof(DWORD) * 7;
	BYTE* buf = new BYTE[count];
	int size = sizeof(DWORD);
	int offset = 0;
	stat.dwTotalPhys /= 1024;
	stat.dwAvailPhys /= 1024;
	stat.dwTotalPageFile /= 1024;
	stat.dwAvailPageFile /= 1024;
	stat.dwTotalVirtual /= 1024;
	stat.dwAvailVirtual /= 1024;

	memcpy(buf + offset, (char*)&stat.dwMemoryLoad, sizeof(DWORD));
	offset += size;
	memcpy(buf + offset, (char*)&stat.dwTotalPhys, sizeof(DWORD));
	offset += size;
	memcpy(buf + offset, (char*)&stat.dwAvailPhys, sizeof(DWORD));
	offset += size;
	memcpy(buf + offset, (char*)&stat.dwTotalPageFile, sizeof(DWORD));
	offset += size;
	memcpy(buf + offset, (char*)&stat.dwAvailPageFile, sizeof(DWORD));
	offset += size;
	memcpy(buf + offset, (char*)&stat.dwTotalVirtual, sizeof(DWORD));
	offset += size;
	memcpy(buf + offset, (char*)&stat.dwAvailVirtual, sizeof(DWORD));
	offset += size;

	DWORD crypt_count = count;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &count, crypt_count);
	count = crypt_count;
	*buffer = new BYTE[count];
	memcpy(*buffer, buf, count);
	*bufSize = count;
}

void getDiskTypes(DWORD *bufSize, BYTE **buffer)
{
	char disks[26][5];
	int n;
	int index = 0;
	DWORD disk_info = GetLogicalDrives();
	for (int i = 0; i < 26; i++)
	{
		n = ((disk_info >> i) & 0x00000001);
		if (n == 1)
		{
			disks[index][0] = char(65 + i);
			disks[index][1] = ':';
			disks[index][2] = 92;
			disks[index][3] = '\0';
			index++;
		}
	}
	for (int i = 0; i < index; i++)
	{
		unsigned int drive_type = GetDriveTypeA((LPCSTR)disks[i]);
		if (drive_type == 2)
		{
			disks[i][3] = '2';
			disks[i][4] = '\0';
		}
		else if (drive_type == 3)
		{
			disks[i][3] = '3';
			disks[i][4] = '\0';
		}
		else if (drive_type == 4)
		{
			disks[i][3] = '4';
			disks[i][4] = '\0';
		}
		else if (drive_type == 5)
		{
			disks[i][3] = '5';
			disks[i][4] = '\0';
		}
		else if (drive_type == 6)
		{
			disks[i][3] = '6';
			disks[i][4] = '\0';
		}
	}
	DWORD size = 4 * index;
	BYTE *buf = new BYTE[size];
	int offset = 0;
	for (int i = 0; i < index; i++)
	{
		memcpy(buf + offset , disks[i], 4);
		offset += 4;
	};
	DWORD crypt_count = size;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &size, crypt_count);
	size = crypt_count;
	*buffer = new BYTE[size];
	memcpy(*buffer, buf, size);
	*bufSize = size;
}

void getFreeSpaceOnDisks(DWORD *bufSize, BYTE **buffer)
{
	char disks[26][5];
	int n;
	int index = 0;
	DWORD disk_info = GetLogicalDrives();
	for (int i = 0; i < 26; i++)
	{
		n = ((disk_info >> i) & 0x00000001);
		if (n == 1)
		{
			disks[index][0] = char(65 + i);
			disks[index][1] = ':';
			disks[index][2] = 92;
			disks[index][3] = '\0';
			index++;
		}
	}
	DWORD count = 0;
	for (int i = 0; i < index; i++)
	{
		if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
			count++;
	};
	DWORD size = 7 * count;
	BYTE* buf = new BYTE[size];
	int offset = 0;
	for (int i = 0; i < index; i++)
	{
		if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
		{
			DWORD s, b, f, c;
			int freeSpace;
			GetDiskFreeSpaceA(disks[i], &s, &b, &f, &c);
			freeSpace = (double)f * (double)s * (double)b / 1024.0 / 1024.0 / 1024.0;
			memcpy(buf + offset, disks[i], 3);
			offset += 3;
			memcpy(buf + offset, &freeSpace, 4);
			offset += 4;
		};
	};
	
	DWORD crypt_count = size;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &size, crypt_count);
	size = crypt_count;
	*buffer = new BYTE[size];
	memcpy(*buffer, buf, size);
	*bufSize = size;
}

void getACL(int mode, DWORD pathSize, BYTE *path, DWORD *bufSize, BYTE **buffer)
{
	CryptDecrypt(hSessionKey, 0, true, 0, path, &pathSize);
	PSECURITY_DESCRIPTOR pSD = NULL;
	PACL dacl = NULL;
	HKEY result;
	if (mode==1) GetNamedSecurityInfo((LPCSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &pSD);
	else if (mode == 2)
	{
		char* key = (char*)malloc((strlen((char*)path) + 1) * sizeof(char*));
		wchar_t* subkey = (wchar_t*)malloc((strlen((char*)path) + 1) * sizeof(wchar_t*));
		char* ptr = (char*)path;
		int i = 0;
		char symb = *ptr;
		while (symb != '\\') {
			key[i] = symb;
			i++;
			ptr++;
			symb = *ptr;
		}
		key[i] = '\0';
		ptr++;
		wsprintf((LPTSTR)subkey, (LPTSTR)L"%hs", ptr);
		if (!strncmp(key, "HKEY_CLASSES_ROOT", strlen("HKEY_CLASSES_ROOT")))
			RegOpenKey(HKEY_CLASSES_ROOT, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_CURRENT_CONFIG", strlen("HKEY_CURRENT_CONFIG")))
			RegOpenKey(HKEY_CURRENT_CONFIG, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_CURRENT_USER", strlen("HKEY_CURRENT_USER")))
			RegOpenKey(HKEY_CURRENT_USER, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_LOCAL_MACHINE", strlen("HKEY_LOCAL_MACHINE")))
			RegOpenKey(HKEY_LOCAL_MACHINE, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_USERS", strlen("HKEY_USERS")))
			RegOpenKey(HKEY_USERS, (LPCTSTR)subkey, &result);
		else return;

		GetSecurityInfo(result, SE_REGISTRY_KEY, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &pSD);
		free(key);
		free(subkey);
	}
	int offset = 0;
	if (dacl == NULL)
	{
		DWORD size = strlen("Incorrected path") + 1;
		BYTE* buf = new BYTE[size];
		memcpy(buf, "Incorrected path", strlen("Incorrected path") + 1);
		DWORD crypt_count = size;
		CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
		buf = (BYTE*)realloc(buf, crypt_count);
		CryptEncrypt(hSessionKey, 0, true, 0, buf, &size, crypt_count);
		size = crypt_count;
		*buffer = new BYTE[size];
		memcpy(*buffer, buf, size);
		*bufSize = size;
		return;
	}
	ACL_SIZE_INFORMATION AclInfo;
	GetAclInformation(dacl, &AclInfo, sizeof(AclInfo), AclSizeInformation);
	int ace_count = AclInfo.AceCount;
	DWORD size = 4 + ace_count * (MAX_PATH + 4 + 4 + 100);
	BYTE* buf = new BYTE[size];
	memcpy(buf + offset, (const char*)&ace_count, sizeof(int));
	offset += sizeof(int);
	for (int i = 0; i < ace_count; i++)
	{
		SID_NAME_USE SidName;
		DWORD len = MAX_PATH;
		char user[MAX_PATH];
		char domain[MAX_PATH];
		void* ace;
		if (GetAce(dacl, i, &ace))
		{
			SID* SidStart = (SID*) & ((ACCESS_ALLOWED_ACE*)ace)->SidStart;
			LookupAccountSid(NULL, SidStart, (LPSTR)user, &len, (LPSTR)domain, &len, &SidName);
			memcpy(buf + offset, user, MAX_PATH);
			offset += MAX_PATH;
			int access;
			if (((ACCESS_ALLOWED_ACE*)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) access = 1;
			else access = 0;
			//memcpy(buf + offset, (const char *)&access, sizeof(int));
			//offset += sizeof(int);
			DWORD mask = (DWORD)((ACCESS_ALLOWED_ACE*)ace)->Mask;
			memcpy(buf + offset, (const char*)&mask, sizeof(DWORD));
			offset += sizeof(DWORD);
			// 100 bytes for SID
			char* sid_str;
			ConvertSidToStringSidA(SidStart, &sid_str);
			int sid_len = strlen(sid_str);
			memcpy(buf + offset, (const char*)&sid_len, sizeof(int));
			offset += sizeof(int);
			memcpy(buf + offset, sid_str, sizeof(char) * sid_len);
			offset += 100;
		}
	}

	DWORD crypt_count = size;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &size, crypt_count);
	size = crypt_count;
	*buffer = new BYTE[size];
	memcpy(*buffer, buf, size);
	*bufSize = size;
}

void getOwner(int mode, DWORD pathSize, BYTE *path, DWORD *bufSize, BYTE **buffer)
{
	CryptDecrypt(hSessionKey, 0, true, 0, path, &pathSize);
	PSECURITY_DESCRIPTOR pSD;
	PSID pOwnerSid = NULL;
	//
	if (mode == 1)
	{
		GetNamedSecurityInfo((LPCSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD);
	}
	else if (mode == 2)
	{
		HKEY result;
		char* key = (char*)malloc((strlen((char*)path) + 1) * sizeof(char*));
		wchar_t* subkey = (wchar_t*)malloc((strlen((char*)path) + 1) * sizeof(wchar_t*));
		char* ptr = (char*)path;
		int i = 0;
		char symb = *ptr;
		while (symb != '\\') {
			key[i] = symb;
			i++;
			ptr++;
			symb = *ptr;
		}
		key[i] = '\0';
		ptr++;
		wsprintf((LPTSTR)subkey, (LPTSTR)L"%hs", ptr);
		if (!strncmp(key, "HKEY_CLASSES_ROOT", strlen("HKEY_CLASSES_ROOT")))
			RegOpenKey(HKEY_CLASSES_ROOT, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_CURRENT_CONFIG", strlen("HKEY_CURRENT_CONFIG")))
			RegOpenKey(HKEY_CURRENT_CONFIG, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_CURRENT_USER", strlen("HKEY_CURRENT_USER")))
			RegOpenKey(HKEY_CURRENT_USER, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_LOCAL_MACHINE", strlen("HKEY_LOCAL_MACHINE")))
			RegOpenKey(HKEY_LOCAL_MACHINE, (LPCTSTR)subkey, &result);
		else if (!strncmp(key, "HKEY_USERS", strlen("HKEY_USERS")))
			RegOpenKey(HKEY_USERS, (LPCTSTR)subkey, &result);
		else return;

		GetSecurityInfo(result, SE_REGISTRY_KEY, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD);
		free(key);
		free(subkey);
	}
	if (pOwnerSid == NULL)
	{
		DWORD size = strlen("Incorrected path") + 1;
		BYTE* buf = new BYTE[size];
		memcpy(buf, "Incorrected path", strlen("Incorrected path") + 1);
		DWORD crypt_count = size;
		CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
		buf = (BYTE*)realloc(buf, crypt_count);
		CryptEncrypt(hSessionKey, 0, true, 0, buf, &size, crypt_count);
		size = crypt_count;
		*buffer = new BYTE[size];
		memcpy(*buffer, buf, size);
		*bufSize = size;
		return;
	}
	char user[MAX_PATH];
	char domain[MAX_PATH];
	unsigned int userLen = MAX_PATH;
	unsigned int domainLen = MAX_PATH;
	SID_NAME_USE SidName;
	DWORD size = MAX_PATH + 4 + 100;
	BYTE* buf = new BYTE[size];
	int offset = 0;
	LookupAccountSid(NULL, pOwnerSid, (LPSTR)user, (LPDWORD)&userLen, (LPSTR)domain, (LPDWORD)&domainLen, &SidName);
	//char user[MAX_PATH];
	//wcstombs(user, wc_user, MAX_PATH);
	memcpy(buf + offset, user, MAX_PATH);
	offset += MAX_PATH;
	char* sid_str;
	ConvertSidToStringSidA(pOwnerSid, &sid_str);
	int sid_len = strlen(sid_str);
	memcpy(buf + offset, (const char*)&sid_len, sizeof(int));
	offset += sizeof(int);
	memcpy(buf + offset, sid_str, sizeof(char) * sid_len);

	DWORD crypt_count = size;
	CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
	buf = (BYTE*)realloc(buf, crypt_count);
	CryptEncrypt(hSessionKey, 0, true, 0, buf, &size, crypt_count);
	size = crypt_count;
	*buffer = new BYTE[size];
	memcpy(*buffer, buf, size);
	*bufSize = size;
}

// Naive security callback.
RPC_STATUS CALLBACK SecurityCallback(RPC_IF_HANDLE /*hInterface*/, void* /*pBindingHandle*/)
{
	return RPC_S_OK; // Always allow anyone.
}

int main()
{
	CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	CryptAcquireContext(&hProvPair, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);

	RPC_STATUS status;

	// Uses the protocol combined with the endpoint for receiving
	// remote procedure calls.
	status = RpcServerUseProtseqEp(
		(unsigned char*)("ncacn_ip_tcp"), // Use TCP/IP protocol.
		RPC_C_PROTSEQ_MAX_REQS_DEFAULT, // Backlog queue length for TCP/IP.
		(unsigned char*)("9000"), // TCP/IP port to use.
		NULL); // No security.

	if (status)
		exit(status);

	// Registers the Example1 interface.
	status = RpcServerRegisterIf2(
		Example1_v1_0_s_ifspec, // Interface to register.
		NULL, // Use the MIDL generated entry-point vector.
		NULL, // Use the MIDL generated entry-point vector.
		RPC_IF_ALLOW_CALLBACKS_WITH_NO_AUTH, // Forces use of security callback.
		RPC_C_LISTEN_MAX_CALLS_DEFAULT, // Use default number of concurrent calls.
		(unsigned)-1, // Infinite max size of incoming data blocks.
		SecurityCallback); // Naive security callback.

	if (status)
		exit(status);
	cout << "Listening at port 9000";
	// Start to listen for remote procedure
	// calls for all registered interfaces.
	// This call will not return until
	// RpcMgmtStopServerListening is called.
	status = RpcServerListen(
		1, // Recommended minimum number of threads.
		RPC_C_LISTEN_MAX_CALLS_DEFAULT, // Recommended maximum number of threads.
		FALSE); // Start listening now.

	if (status)
		exit(status);

	// Освобождение контекста захваченных провайдеров
	CryptReleaseContext(hProvPair, 0);
	CryptReleaseContext(hProv, 0);
}

// Memory allocation function for RPC.
// The runtime uses these two functions for allocating/deallocating
// enough memory to pass the string to the server.
void* __RPC_USER midl_user_allocate(size_t size)
{
	return malloc(size);
}

// Memory deallocation function for RPC.
void __RPC_USER midl_user_free(void* p)
{
	free(p);
}