#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
#define WIN32_LEAN_AND_MEAN
#include <stdio.h>
#include <WinSock2.h>
#include <windows.h>
#include <stdlib.h>
#include <conio.h>
#include <MSWSock.h>
#include <ctype.h>
#include <iostream>
#include <wincrypt.h>
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "mswsock.lib")

#define MAX_CLIENTS (100)
#define MAX_PATH 260
#define WIN32_LEAN_AND_MEAN
struct client_ctx
{
	int sock;
	CHAR buf_recv[512]; // Буфер приема
	CHAR buf_send[512]; // Буфер отправки
	unsigned int sz_recv; // Принято данных
	unsigned int sz_send_total; // Данных в буфере отправки
	unsigned int sz_send; // Данных отправлено
	int flag_op;
	bool flag_key;
	// Структуры OVERLAPPED для уведомлений о завершении
	OVERLAPPED overlap_recv;
	OVERLAPPED overlap_send;
	OVERLAPPED overlap_cancel;
	HCRYPTKEY sessionKey;
	DWORD flags_recv; // Флаги для WSARecv
};
// Прослушивающий сокет и все сокеты подключения хранятся
// в массиве структур (вместе с overlapped и буферами)
struct client_ctx arr[1 + MAX_CLIENTS];
int g_accepted_socket;
HANDLE g_io_port;
bool flag_key = false;

//Функция выбора операции для отправки клиенту
void choose_operation(int idx)
{
	if (!strcmp(arr[idx].buf_recv, "OS"))
		arr[idx].flag_op = 1;
	else if (!strcmp(arr[idx].buf_recv, "CurTime"))
		arr[idx].flag_op = 2;
	else if (!strcmp(arr[idx].buf_recv, "TimeLaunch"))
		arr[idx].flag_op = 3;
	else if (!strcmp(arr[idx].buf_recv, "Memory"))
		arr[idx].flag_op = 4;
	else if (!strcmp(arr[idx].buf_recv, "Disk"))
		arr[idx].flag_op = 5;
	else if (!strcmp(arr[idx].buf_recv, "Free"))
		arr[idx].flag_op = 6;
	else if (arr[idx].buf_recv[0] == 'A' && arr[idx].buf_recv[1] == 'C' && arr[idx].buf_recv[2] == 'L')
		arr[idx].flag_op = 7;
	else if (arr[idx].buf_recv[0] == 'O' && arr[idx].buf_recv[1] == 'w' && arr[idx].buf_recv[2] == 'n')
		arr[idx].flag_op = 8;
}
// Функция стартует операцию чтения из сокета
void schedule_read(DWORD idx)
{
	WSABUF buf;
	buf.buf = arr[idx].buf_recv + arr[idx].sz_recv;
	buf.len = sizeof(arr[idx].buf_recv) - arr[idx].sz_recv;
	memset(&arr[idx].overlap_recv, 0, sizeof(OVERLAPPED));
	arr[idx].flags_recv = 0;
	WSARecv(arr[idx].sock, &buf, 1, NULL, &arr[idx].flags_recv, &arr[idx].overlap_recv, NULL);
}
void reverse(char s[])
{
	int i, j;
	char c;

	for (i = 0, j = strlen(s) - 1; i<j; i++, j--) {
		c = s[i];
		s[i] = s[j];
		s[j] = c;
	}
}
void itoa(int n, char s[])
{
	int i, sign;

	if ((sign = n) < 0)  /* записываем знак */
		n = -n;          /* делаем n положительным числом */
	i = 0;
	do {       /* генерируем цифры в обратном порядке */
		s[i++] = n % 10 + '0';   /* берем следующую цифру */
	} while ((n /= 10) > 0);     /* удаляем */
	if (sign < 0)
		s[i++] = '-';
	s[i] = '\0';
	reverse(s);
}
// Функция стартует операцию отправки подготовленных данных в сокет
void schedule_write(DWORD idx)
{
	switch (arr[idx].flag_op)
	{
	case 1://Готово и зашифровано
	{
		NET_API_STATUS nStatus;
		DWORD dwLevel = 101;
		LPSERVER_INFO_101 pBuf;
		LPWSTR pszServerName = NULL;
		NetServerGetInfo(pszServerName, dwLevel, (LPBYTE *)&pBuf);
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

		WSABUF buf;
		buf.buf = (char*)osVersion;
		buf.len = strlen(osVersion) + 1;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(buf.len * sizeof(BYTE));
		memcpy(data, buf.buf, buf.len);
		//data[buf.len] = '\0';
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, buf.len);
		data = (BYTE*)realloc(data, enc * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &buf.len, enc);
		buf.buf = (char*)data;
		WSASend(arr[idx].sock, &buf, 1, NULL, 0, &arr[idx].overlap_send, NULL);
		break;
	}
	case 2://Готово и зашифровано
	{
		SYSTEMTIME sm;
		GetSystemTime(&sm);
		int hour, minute, second, day, month, year;
		WSABUF wd[1];
		hour = (sm.wHour + 3) % 24;
		minute = sm.wMinute;
		second = sm.wSecond;
		day = sm.wDay;
		month = sm.wMonth;
		year = sm.wYear;
		int size = sizeof(WORD);
		int offset = 0;
		int count = size * 6;
		BYTE* buf = new BYTE[count];
		
		memcpy(buf + offset, &hour, size);
		offset += size;
		memcpy(buf + offset, &minute, size);
		offset += size;
		memcpy(buf + offset, &second, size);
		offset += size;
		memcpy(buf + offset, &day, size);
		offset += size;
		memcpy(buf + offset, &month, size);
		offset += size;
		memcpy(buf + offset, &year, size);

		wd[0].len = count;
		wd[0].buf = (char*)buf;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf, wd[0].len);
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, enc * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc);
		wd[0].buf = (char*)data;

		WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);
		break;
	}
	case 3://Готово и зашифровано
	{
		DWORD hour, min, sec;
		unsigned long  msec = GetTickCount();
		hour = msec / (1000 * 60 * 60);
		min = msec / (1000 * 60) - hour * 60;
		sec = (msec / 1000) - (hour * 60 * 60) - min * 60;

		WSABUF wd[1];

		DWORD count = sizeof(unsigned long) * 3;
		BYTE* buf = new BYTE[count];
		memcpy(buf, (char*)&hour, sizeof(unsigned long));
		memcpy(buf + 4, (char*)&min, sizeof(unsigned long));
		memcpy(buf + 8, (char*)&sec, sizeof(unsigned long));

		wd[0].len = count;
		wd[0].buf = (char*)buf;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf, wd[0].len);
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, enc * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc);
		wd[0].buf = (char*)data;

		WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);
		break;
	}
	case 4://Готово и зашифровано
	{
		WSABUF wd[1];
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

		wd[0].len = count;
		wd[0].buf = (char*)buf;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf, wd[0].len);
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
		wd[0].buf = (char*)data;

		WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);

		break;
	}
	case 5://Готово и зашифровано
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
		WSABUF wd[1];
		DWORD size = 4 * index;
		BYTE* buf = new BYTE[size];
		int offset = 0;
		for (int i = 0; i < index; i++)
		{
			memcpy(buf + offset, disks[i], 4);
			offset += 4;
		};
		wd[0].buf = (char*)buf;
		wd[0].len = size;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf, wd[0].len);
		data[wd[0].len] = '\0';
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
		wd[0].buf = (char*)data;
		WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);
		break;
	}
	case 6://Готово и зашифровано
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
		int count = 0;
		for (int i = 0; i < index; i++)
		{
			if (GetDriveTypeA(disks[i]) == DRIVE_FIXED)
				count++;
		}
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
		WSABUF wd[1];
		wd[0].buf = (char*)buf;
		wd[0].len = size;
		DWORD enc = 0;
		BYTE* data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf, wd[0].len);
		data[wd[0].len] = '\0';
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
		wd[0].buf = (char*)data;
		WSASend(arr[idx].sock, wd, idx, NULL, 0, &arr[idx].overlap_send, NULL);
		break;
	}
	case 7://Готово и зашифровано
	{
		/**/char path[300] = { 0 };
		int size_str = 0;
		char num = arr[idx].buf_recv[3];
		for (int i = 4; i < strlen(arr[idx].buf_recv); i++)
		{
			path[i - 4] = (wchar_t)arr[idx].buf_recv[i];
			size_str++;
		}
		path[size_str] = L'\0';
		PSECURITY_DESCRIPTOR pSD = NULL;
		PACL dacl = NULL;
		HKEY result;
		if (num == '1') GetNamedSecurityInfo((LPCSTR)path, SE_FILE_OBJECT, DACL_SECURITY_INFORMATION, NULL, NULL, &dacl, NULL, &pSD);
		else if (num == '2')
		{
			char* key = (char*)malloc((strlen(path) + 1) * sizeof(char*));
			wchar_t* subkey = (wchar_t*)malloc((strlen(path) + 1) * sizeof(wchar_t*));
			char* ptr = path;
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
		WSABUF wd[1];
		wd[0].len = 0;
		int offset = 0;
		if (dacl == NULL)
		{
			BYTE* buf = (BYTE*)malloc(strlen("Incorrected path")+1 * sizeof(BYTE));
			memcpy(buf, "Incorrected path", strlen("Incorrected path") + 1);
			wd[0].buf = (char*)buf;
			wd[0].len = strlen("Incorrected path") + 1;
			DWORD enc = 0;
			BYTE* data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
			memcpy(data, buf, wd[0].len);
			//data[wd[0].len] = '\0';
			int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
			data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
			int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
			wd[0].buf = (char*)data;

			WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);/**/
			break;
		}

		ACL_SIZE_INFORMATION AclInfo;
		GetAclInformation(dacl, &AclInfo, sizeof(AclInfo), AclSizeInformation);
		int ace_count = AclInfo.AceCount;
		DWORD size = 4 + 10 * (MAX_PATH + 4 + 100);
		BYTE *buf = (BYTE*)malloc(size * sizeof(BYTE));
		memcpy(buf + offset, (const char *)&ace_count, sizeof(int));
		offset += sizeof(int);
		wd[0].len += sizeof(int);
		for (int i = 0; i < ace_count; i++)
		{
			SID_NAME_USE SidName;
			DWORD len = MAX_PATH;
			char user[MAX_PATH];
			char domain[MAX_PATH];
			void *ace;
			if (GetAce(dacl, i, &ace))
			{
				SID *SidStart = (SID *) &((ACCESS_ALLOWED_ACE *)ace)->SidStart;
				LookupAccountSid(NULL, SidStart, (LPSTR)user, &len, (LPSTR)domain, &len, &SidName);
				memcpy(buf + offset, user, MAX_PATH);
				offset += MAX_PATH;
				int access;
				if (((ACCESS_ALLOWED_ACE *)ace)->Header.AceType == ACCESS_ALLOWED_ACE_TYPE) access = 1;
				else access = 0;
				//memcpy(buf + offset, (const char *)&access, sizeof(int));
				//offset += sizeof(int);
				DWORD mask = (DWORD)((ACCESS_ALLOWED_ACE *)ace)->Mask;
				memcpy(buf + offset, (const char *)&mask, sizeof(DWORD));
				offset += sizeof(DWORD);
				// 100 bytes for SID
				char *sid_str;
				ConvertSidToStringSidA(SidStart, &sid_str);
				int sid_len = strlen(sid_str);
				memcpy(buf + offset, (const char*)&sid_len, sizeof(int));
				offset += sizeof(int);
				memcpy(buf + offset, sid_str, sizeof(char) * sid_len);
				offset += 100;
				wd[0].len += (MAX_PATH + 4+4 + 100);
			}
		}

		wd[0].buf = (char*)buf;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf, wd[0].len);
		//data[wd[0].len] = '\0';
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
		wd[0].buf = (char*)data;

		WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);/**/
		break;
	}
	case 8://Готово и зашифровано
	{
		PSECURITY_DESCRIPTOR pSD;
		PSID pOwnerSid = NULL;
		char path[300];
		int size_str = 0;
		char buf_num = arr[idx].buf_recv[3];
		for (int i = 4; i < strlen(arr[idx].buf_recv); i++)
		{
			path[i - 4] = (wchar_t)arr[idx].buf_recv[i];
			size_str++;
		}
		path[size_str] = L'\0';
		if (buf_num == '1')
		{
			GetNamedSecurityInfo((LPCSTR)path, SE_FILE_OBJECT, OWNER_SECURITY_INFORMATION, &pOwnerSid, NULL, NULL, NULL, &pSD);
		}
		else if (buf_num == '2')
		{
			HKEY result;
			char* key = (char*)malloc((strlen(path) + 1) * sizeof(char*));
			wchar_t* subkey = (wchar_t*)malloc((strlen(path) + 1) * sizeof(wchar_t*));
			char* ptr = path;
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
		WSABUF wd[1];
		wd[0].len = 0;
		if (pOwnerSid == NULL)
		{
			BYTE* buf = (BYTE*)malloc(strlen("Incorrected path") + 1 * sizeof(BYTE));
			memcpy(buf, "Incorrected path", strlen("Incorrected path") + 1);
			wd[0].buf = (char*)buf;
			wd[0].len = strlen("Incorrected path") + 1;
			DWORD enc = 0;
			BYTE* data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
			memcpy(data, buf, wd[0].len);
			//data[wd[0].len] = '\0';
			int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
			data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
			int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
			wd[0].buf = (char*)data;

			WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);/**/
			break;
		}
		char user[MAX_PATH];
		char domain[MAX_PATH];
		unsigned int userLen = MAX_PATH;
		unsigned int domainLen = MAX_PATH;
		SID_NAME_USE SidName;
		DWORD size = MAX_PATH + 4 + 100;
		BYTE *buf_send = (BYTE*)malloc(size * sizeof(BYTE));

		int offset = 0;
		LookupAccountSid(NULL, pOwnerSid, (LPSTR)user, (LPDWORD)&userLen, (LPSTR)domain, (LPDWORD)&domainLen, &SidName);
		//char user[MAX_PATH];
		//wcstombs(user, wc_user, MAX_PATH);
		memcpy(buf_send + offset, user, MAX_PATH);
		offset += MAX_PATH;
		char *sid_str;
		ConvertSidToStringSidA(pOwnerSid, &sid_str);
		int sid_len = strlen(sid_str);
		memcpy(buf_send + offset, (const char*)&sid_len, sizeof(int));
		offset += sizeof(int);
		memcpy(buf_send + offset, sid_str, sizeof(char) * sid_len);

		wd[0].len = size;//*/
		wd[0].buf = (char*)buf_send;
		DWORD enc = 0;
		BYTE *data = (BYTE*)malloc(wd[0].len * sizeof(BYTE));
		memcpy(data, buf_send, wd[0].len);
		//data[wd[0].len] = '\0';
		int f7 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, NULL, &enc, wd[0].len);
		data = (BYTE*)realloc(data, (enc + wd[0].len) * sizeof(BYTE));
		int f8 = CryptEncrypt(arr[idx].sessionKey, NULL, TRUE, NULL, data, &wd[0].len, enc + wd[0].len);
		wd[0].buf = (char*)data;

		WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);
		break;
	}
	default:
		return;
	}
}

// Функция добавляет новое принятое подключение клиента
void add_accepted_connection()
{
	DWORD i; // Поиск места в массиве arr для вставки нового подключения
	for (i = 0; i < sizeof(arr) / sizeof(arr[0]); i++)
	{
		if (arr[i].sock == 0)
		{
			unsigned int ip = 0;
			struct sockaddr_in* local_addr = 0, *remote_addr = 0;
			int local_addr_sz, remote_addr_sz;
			GetAcceptExSockaddrs(arr[0].buf_recv, arr[0].sz_recv, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, (struct sockaddr **) &local_addr, &local_addr_sz, (struct sockaddr **) &remote_addr, &remote_addr_sz);
			if (remote_addr) ip = ntohl(remote_addr->sin_addr.s_addr);
			printf(" connection %u created, remote IP: %u.%u.%u.%u\n", i, (ip >> 24) & 0xff, (ip >> 16) & 0xff, (ip >> 8) & 0xff, (ip) & 0xff);
			arr[i].sock = g_accepted_socket;
			// Связь сокета с портом IOCP, в качестве key используется индекс массива
			if (NULL == CreateIoCompletionPort((HANDLE)arr[i].sock, g_io_port, i, 0))
			{
				printf("CreateIoCompletionPort error: %x\n", GetLastError());
				return;
			}
			// Ожидание данных от сокета
			schedule_read(i);
			return;
		}
	}
	// Место не найдено => нет ресурсов для принятия соединения
	closesocket(g_accepted_socket);
	g_accepted_socket = 0;
}
// Функция стартует операцию приема соединения
void schedule_accept()
{
	// Создание сокета для принятия подключения (AcceptEx не создает сокетов)
	g_accepted_socket = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	memset(&arr[0].overlap_recv, 0, sizeof(OVERLAPPED));
	// Принятие подключения.
	// Как только операция будет завершена - порт завершения пришлет уведомление. // Размеры буферов должны быть на 16 байт больше размера адреса согласно документации разработчика ОС
	AcceptEx(arr[0].sock, g_accepted_socket, arr[0].buf_recv, 0, sizeof(struct sockaddr_in) + 16, sizeof(struct sockaddr_in) + 16, NULL, &arr[0].overlap_recv);
}

void create_and_send_sessionkey(int idx)
{
	BYTE buffer_key[4200];
	memcpy(buffer_key, arr[idx].buf_recv, arr[idx].sz_recv);
	//publ
	HCRYPTPROV hprov;
	HCRYPTKEY publicKey;
	//sessio
	HCRYPTPROV sesprov;;
	//Теперь надо сделать сессионный
	int f1 = CryptAcquireContext(&sesprov, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	int f2 = CryptGenKey(sesprov, CALG_AES_256, 0x01000000 | CRYPT_EXPORTABLE, &arr[idx].sessionKey);
	//Выясняем сколько надо на отправку сессионного ключа
	DWORD count = 0;
	BYTE *data;
	int f3 = CryptExportKey(arr[idx].sessionKey, 0, PLAINTEXTKEYBLOB, 0, NULL, &count);
	data = (BYTE*)malloc(count * sizeof(BYTE));
	int f4 = CryptExportKey(arr[idx].sessionKey, 0, PLAINTEXTKEYBLOB, 0, data, &count);
	//Достали публичный ключ
	int f5 = CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	int f6 = CryptImportKey(hprov, buffer_key, arr[idx].sz_recv, NULL, NULL, &publicKey);
	DWORD enc = 0;
	int f7 = CryptEncrypt(publicKey, NULL, TRUE, NULL, NULL, &enc, count);
	data = (BYTE*)realloc(data, enc * sizeof(BYTE));
	int f8 = CryptEncrypt(publicKey, NULL, TRUE, NULL, data, &count, enc);

	WSABUF wd[1];
	memcpy(arr[idx].buf_send, data, enc);
	wd[0].buf = arr[idx].buf_send;
	wd[0].len = enc;
	WSASend(arr[idx].sock, wd, 1, NULL, 0, &arr[idx].overlap_send, NULL);
}
void io_serv()
{
	setlocale(LC_ALL, "Russian");
	WSADATA wsa_data;
	if (WSAStartup(MAKEWORD(2, 2), &wsa_data) == 0)
	{
		printf("WSAStartup ok\n");
	}
	else
	{
		printf("WSAStartup error\n");
	}
	struct sockaddr_in addr;
	// Создание сокета прослушивания
	SOCKET s = WSASocket(AF_INET, SOCK_STREAM, 0, NULL, 0, WSA_FLAG_OVERLAPPED);
	// Создание порта завершения
	g_io_port = CreateIoCompletionPort(INVALID_HANDLE_VALUE, NULL, 0, 0);
	if (NULL == g_io_port)
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	// Обнуление структуры данных для хранения входящих соединений
	memset(arr, 0, sizeof(arr));
	memset(&addr, 0, sizeof(addr)); addr.sin_family = AF_INET; addr.sin_port = htons(9000);
	if (bind(s, (struct sockaddr*) &addr, sizeof(addr)) < 0 || listen(s, 1) < 0)
	{
		printf("error bind() or listen()\n");
		return;
	}
	printf("Listening: %hu\n", ntohs(addr.sin_port));
	// Присоединение существующего сокета s к порту io_port.
	// В качестве ключа для прослушивающего сокета используется 0
	if (NULL == CreateIoCompletionPort((HANDLE)s, g_io_port, 0, 0))
	{
		printf("CreateIoCompletionPort error: %x\n", GetLastError());
		return;
	}
	arr[0].sock = s;
	// Старт операции принятия подключения.
	schedule_accept();
	// Бесконечный цикл принятия событий о завершенных операциях
	while (1)
	{
		DWORD transferred;
		ULONG_PTR key;
		OVERLAPPED* lp_overlap;
		// Ожидание событий в течение 1 секунды
		BOOL b = GetQueuedCompletionStatus(g_io_port, &transferred, &key, &lp_overlap, 1000);
		if (b)
		{
			// Поступило уведомление о завершении операции
			if (key == 0) // ключ 0 - для прослушивающего сокета
			{
				arr[0].sz_recv += transferred;
				// Принятие подключения и начало принятия следующего
				add_accepted_connection();
				schedule_accept();
			}
			else
			{
				// Иначе поступило событие по завершению операции от клиента. // Ключ key - индекс в массиве arr
				if (&arr[key].overlap_recv == lp_overlap)
				{
					//Если символ - буква, то пришла операция - иначе ключ
					if (arr[key].flag_key == false)
					{
						arr[key].sz_recv += transferred;
						create_and_send_sessionkey(key);
						continue;
					}

					int len = strlen(arr[key].buf_recv);
					// Данные приняты:
					if (transferred == 0)
					{
						// Соединение разорвано
						//CancelIo((HANDLE)arr[key].socket);
						//PostQueuedCompletionStatus(g_io_port, 0, key, &arr[key].overlap_recv);
						continue;
					}
					arr[key].sz_recv += transferred;
					// Если строка полностью пришла, то сформировать ответ и начать его отправлять
					//sprintf(arr[key].buf_send, "You string length: %d\n", len);
					choose_operation(key);
					arr[key].sz_send_total = strlen(arr[key].buf_send);
					arr[key].sz_send = 0;
					schedule_write(key);
				}
				else if (&arr[key].overlap_send == lp_overlap)
				{
					if (arr[key].flag_key == false)
					{
						arr[key].flag_key = true;
						memset(&arr[key].buf_recv, 0, sizeof(arr[key].buf_recv));
						memset(&arr[key].buf_send, 0, sizeof(arr[key].buf_send));
						arr[key].sz_recv = 0;
						arr[key].sz_send = 0;
						arr[key].sz_send_total = 0;
						schedule_read(key);
						continue;
					}
					// Данные отправлены
					arr[key].sz_send += transferred;
					if (arr[key].sz_send < arr[key].sz_send_total && transferred > 0)
					{
						// Если данные отправлены не полностью - продолжить отправлять
						schedule_write(key);
					}
					else
					{
						// Данные отправлены полностью, прервать все коммуникации,
						// добавить в порт событие на завершение работы
						//CancelIo((HANDLE)arr[key].socket);
						//PostQueuedCompletionStatus(g_io_port, 0, key, &arr[key].overlap_recv);
						memset(&arr[key].buf_recv, 0, sizeof(arr[key].buf_recv));
						memset(&arr[key].buf_send, 0, sizeof(arr[key].buf_send));
						arr[key].sz_recv = 0;
						arr[key].sz_send = 0;
						arr[key].sz_send_total = 0;
						schedule_read(key);
					}
				}
				else if (&arr[key].overlap_cancel == lp_overlap)
				{
					// Все коммуникации завершены, сокет может быть закрыт
					closesocket(arr[key].sock); memset(&arr[key], 0, sizeof(arr[key]));
					printf(" connection %u closed\n", key);
				}
			}
		}
		else
		{
			// Ни одной операции не было завершено в течение заданного времени, программа может
			// выполнить какие-либо другие действия
			// ...
		}
	}
}
int main()
{
	io_serv();
	return 0;
}