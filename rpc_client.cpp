#define _CRT_SECURE_NO_WARNINGS
#include <iostream>
#include <fstream>

#include "bsit1_h.h"

#pragma comment(lib, "Rpcrt4.lib")

using namespace std;
HCRYPTKEY hSessionKey;

void print_menu()
{
	puts("You can use any of these commands by typing their number:");
	puts("//-----------------------------------------//");
	puts("1 - Type of OS\n");
	puts("2 - Current time\n");
	puts("3 - Time since launch\n");
	puts("4 - Info about memory\n");
	puts("5 - Types of connected disks\n");
	puts("6 - Free space on local disks\n");
	puts("7 - ACL for your file/dir/registry key\n");
	puts("8 - Owner of file/dir/registry key\n");
	puts("9 - Quit");
	puts("//-----------------------------------------//");
}

void crypt_transfer(void)
{
	HCRYPTPROV hProv;
	HCRYPTKEY hPublicKey;
	//Создание контейнера ключей
	CryptAcquireContext(&hProv, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	//Создаем публичный/приватный ключ
	CryptGenKey(hProv, CALG_RSA_KEYX, RSA1024BIT_KEY, &hPublicKey);
	//Готовим публичный ключ к отправке, узнаем размер массива на отпраку
	DWORD count = 0;
	CryptExportKey(hPublicKey, NULL, PUBLICKEYBLOB, 0, NULL, &count);
	BYTE* pKey = new BYTE[count];
	CryptExportKey(hPublicKey, NULL, PUBLICKEYBLOB, 0, pKey, &count);

	DWORD sessionKeySize = 0;
	BYTE* sessionKey = NULL;
	getSessionKey(count, pKey, &sessionKeySize, &sessionKey);

	CryptDecrypt(hPublicKey, 0, true, 0, sessionKey, &sessionKeySize);
	HCRYPTPROV hProvServer;
	CryptAcquireContext(&hProvServer, NULL, NULL, PROV_RSA_AES, CRYPT_VERIFYCONTEXT);
	CryptImportKey(hProvServer, sessionKey, sessionKeySize, 0, 0, &hSessionKey);

	delete[] sessionKey;
}

void operationPerform()
{
	print_menu();
	RpcTryExcept
	{
		crypt_transfer();
		while (true)
		{

			int command;
			char path[MAX_PATH];

			DWORD bufSize = 0;
			BYTE* buf = NULL;
			BYTE* buff = NULL;
			DWORD crypt_count = 0;
			DWORD count = 0;
			cout << "Enter command: ";
			cin >> command;
			switch (command)
			{
			case 1://ready
				getOsVersion(&bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				cout << "OS version is " << buf << endl;
				delete[] buf;
				break;

			case 2://ready
				getCurrentTime(&bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				{
					char temp_buf[4];
					memcpy(temp_buf, buf, 4);
					DWORD hour = (int&)*temp_buf;
					memcpy(temp_buf, buf + 4, 4);
					DWORD minute = (int&)*temp_buf;
					memcpy(temp_buf, buf + 8, 4);
					DWORD second = (int&)*temp_buf;
					memcpy(temp_buf, buf + 12, 4);
					DWORD day = (int&)*temp_buf;
					memcpy(temp_buf, buf + 16, 4);
					DWORD month = (int&)*temp_buf;
					memcpy(temp_buf, buf + 20, 4);
					DWORD year = (int&)*temp_buf;
					cout << "Current time and date: " << hour << ':' << minute << ':' << second << " " << day << '.' << month << '.' << year << endl;
					delete[] buf;
				};
				break;

			case 3://ready
				getTimeFromBootOS(&bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				{
					char temp_buf[4];
					memcpy(temp_buf, buf, 4);
					unsigned int hour = (int&)*temp_buf;
					memcpy(temp_buf, buf + 4, 4);
					unsigned int minute = (int&)*temp_buf;
					memcpy(temp_buf, buf + 8, 4);
					unsigned int second = (int&)*temp_buf;
					cout << "Time since launching: " << hour << ':' << minute << ':' << second << endl;
				}
				delete[] buf;
				break;

			case 4:
				getMemoryStatus(&bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				{
					char temp_buf[4];
					int size = sizeof(DWORD);
					int offset = 0;
					memcpy(temp_buf, buf + offset, size);
					DWORD MemoryLoad = (int&)*temp_buf;
					offset += size;

					memcpy(temp_buf, buf + offset, size);
					DWORD TotalPhys = (int&)*temp_buf;
					offset += size;

					memcpy(temp_buf, buf + offset, size);
					DWORD AvailPhys = (int&)*temp_buf;
					offset += size;

					memcpy(temp_buf, buf + offset, size);
					DWORD TotalPF = (int&)*temp_buf;
					offset += size;

					memcpy(temp_buf, buf + offset, size);
					DWORD AvailPF = (int&)*temp_buf;
					offset += size;

					memcpy(temp_buf, buf + offset, size);
					DWORD TotalVirtual = (int&)*temp_buf;
					offset += size;

					memcpy(temp_buf, buf + offset, size);
					DWORD AvailVirtual = (int&)*temp_buf;

					cout << "Memory load: " << MemoryLoad << "%" << endl;
					cout << "Total amount of phys memory: " << TotalPhys << " Kbytes" << endl;
					cout << "Available phys memory: " << AvailPhys << " Kbytes" << endl;
					cout << "Max amount of memory for programms: " << TotalPF << " Kbytes" << endl;
					cout << "Available amount of memory for programms: " << AvailPF << " Kbytes" << endl;
					cout << "Max amount of virtual memory: " << TotalVirtual << " Kbytes" << endl;
					cout << "Availbale amount of virtual memory: " << AvailVirtual << " Kbytes" << endl;
				}
				delete[] buf;
				break;

			case 5:
				getDiskTypes(&bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				{
					int num = bufSize / 4;
					char buf_litera[5];
					char buf_num;
					for (int i = 0; i < num; i++)
					{
						memset(&buf_litera, 0, 5);
						buf_num = 0;
						memcpy(buf_litera, buf + i * 4, 3);
						buf_litera[4] = '\0';
						buf_num = buf[i * 4 + 3];
						cout << "Disk " << buf_litera;
						if (buf_num == '2')
							cout << " - Floopy drive, thumb drive or flash card reader" << endl;
						else if (buf_num == '3')
							cout << " - Hard disk drive of flash drive" << endl;
						else if (buf_num == '4')
							cout << " - Remote/network drive" << endl;
						else if (buf_num == '5')
							cout << " - CD-ROM drive" << endl;
						else if (buf_num == '6')
							cout << " - RAM disk" << endl;
					}
				}
				delete[] buf;

				break;

			case 6:
				getFreeSpaceOnDisks(&bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);//192.168.1.4:9000
				{
					int num = bufSize / 7;
					int offset = 0;
					for (int i = 0; i < num; i++)
					{
						char buf_litera[4];
						memcpy(buf_litera, buf + offset, 3);
						buf_litera[3] = '\0';
						offset += 3;
						char buf_size[4];
						memcpy(buf_size, buf + offset, 4);
						offset += 4;
						int disk_size = (int&)(*buf_size);
						cout << "Disk " << buf_litera << " has " << disk_size << " GB of free space" << endl;
					}
				}
				delete[] buf;

				break;

			case 7://ready
			{
				setlocale(LC_ALL, "Russian");
				cout << "Enter the path to file: ";
				cin.ignore(1, '\n');
				cin.getline(path, MAX_PATH, '\n');
				cout << "If it's file/dir enter 1, key - 2: ";
				int mode;
				cin >> mode;
				crypt_count = MAX_PATH;
				CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
				buff = new BYTE[crypt_count];
				memcpy(buff, path, MAX_PATH);
				count = MAX_PATH;
				CryptEncrypt(hSessionKey, 0, true, 0, buff, &count, crypt_count);
				getACL(mode, crypt_count, buff, &bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				if (!strcmp((char*)buf, "Incorrected path"))
				{
					cout << "Incorrected path. Try again." << endl;
					break;
				};
				char temp_buf[4];
				int offset = 0;
				memcpy(temp_buf, buf + offset, sizeof(int));
				offset += sizeof(int);
				int ace_count = (int&)*temp_buf;

				char user[MAX_PATH];
				char SID_str[101];

				for (int i = 0; i < ace_count; i++)
				{
					memcpy(user, buf + offset, MAX_PATH);
					offset += MAX_PATH;

					memcpy(temp_buf, buf + offset, sizeof(int));
					offset += sizeof(int);
					int mask = (int&)*temp_buf;

					memcpy(temp_buf, buf + offset, sizeof(int));
					offset += sizeof(int);
					int sid_len = (int&)*temp_buf;

					memcpy(SID_str, buf + offset, 100);
					offset += 100;
					SID_str[sid_len] = '\0';
					cout << "User: " << user << " with SID: " << SID_str << endl
						<< "Access rights:\n";
					if (mode == 1)
					{
						if (mask & FILE_READ_DATA)
							cout << "\tFILE_READ_DATA" << endl;
						if (mask & FILE_WRITE_DATA) // or directory FILE_ADD_FILE (0x0002)
							cout << "\tFILE_WRITE_DATA" << endl;
						if (mask & FILE_APPEND_DATA) // or directory FILE_ADD_SUBDIRECTORY (0x0004)
							cout << "\tFILE_APPEND_DATA" << endl;
						if (mask & FILE_READ_EA)
							cout << "\tFILE_READ_EA" << endl;
						if (mask & FILE_WRITE_EA)
							cout << "\tFILE_WRITE_EA" << endl;
						if (mask & FILE_EXECUTE) // or directory FILE_TRAVERSE (0x0020)
							cout << "\tFILE_EXECUTE" << endl;
						if (mask & FILE_DELETE_CHILD) // only for directory
							cout << "\tFILE_DELETE_CHILD" << endl;
						if (mask & FILE_READ_ATTRIBUTES)
							cout << "\tFILE_READ_ATTRIBUTES" << endl;
						if (mask & FILE_WRITE_ATTRIBUTES)
							cout << "\tFILE_WRITE_ATTRIBUTES" << endl;
					}
					else
					{
						if (mask & KEY_QUERY_VALUE)
							cout << "\tKEY_QUERY_VALUE" << endl;
						if (mask & KEY_SET_VALUE)
							cout << "\tKEY_SET_VALUE" << endl;
						if (mask & KEY_CREATE_SUB_KEY)
							cout << "\tKEY_CREATE_SUB_KEY" << endl;
						if (mask & KEY_ENUMERATE_SUB_KEYS)
							cout << "\tKEY_ENUMERATE_SUB_KEYS " << endl;
						if (mask & KEY_NOTIFY)
							cout << "\tKEY_NOTIFY" << endl;
						if (mask & KEY_CREATE_LINK)
							cout << "\tKEY_CREATE_LINK " << endl;
						if (mask & KEY_WOW64_32KEY)
							cout << "\tKEY_WOW64_32KEY" << endl;
						if (mask & KEY_WOW64_64KEY)
							cout << "\tKEY_WOW64_64KEY " << endl;
						if (mask & KEY_WOW64_RES)
							cout << "\tKEY_WOW64_RES" << endl;
						if (mask & KEY_READ)
							cout << "\tKEY_READ" << endl;
						if (mask & KEY_WRITE)
							cout << "\tKEY_WRITE" << endl;
						if (mask & KEY_EXECUTE)
							cout << "\tKEY_EXECUTE" << endl;
						if (mask & KEY_ALL_ACCESS)
							cout << "\tKEY_ALL_ACCESS" << endl;
					}
					cout << "Standard access types:" << endl;
					if (mask & DELETE)
						cout << "\tDELETE" << endl;
					if (mask & READ_CONTROL)
						cout << "\tREAD_CONTROL" << endl;
					if (mask & WRITE_DAC)
						cout << "\tWRITE_DAC" << endl;
					if (mask & WRITE_OWNER)
						cout << "\tWRITE_OWNER" << endl;
					if (mask & SYNCHRONIZE)
						cout << "\tSYNCHRONIZE" << endl;
					if (mask & GENERIC_READ)
						cout << "\tGENERIC_READ" << endl;
					if (mask & GENERIC_WRITE)
						cout << "\tGENERIC_WRITE" << endl;
					if (mask & GENERIC_EXECUTE)
						cout << "\tGENERIC_EXECUTE" << endl;
					if (mask & GENERIC_ALL)
						cout << "\tGENERIC_ALL" << endl;
					cout << endl;
				}
				delete[] buf;
			}
				break;

			case 8://ready
			{
				setlocale(LC_ALL, "Russian");
				cout << "Enter the path to file: ";
				cin.ignore(1, '\n');
				cin.getline(path, MAX_PATH, '\n');
				cout << "If it's file/dir enter 1, key - 2: ";
				int mode;
				cin >> mode;
				crypt_count = MAX_PATH;
				CryptEncrypt(hSessionKey, 0, true, 0, NULL, &crypt_count, 0);
				buff = new BYTE[crypt_count];
				memcpy(buff, path, MAX_PATH);
				count = MAX_PATH;
				CryptEncrypt(hSessionKey, 0, true, 0, buff, &count, crypt_count);
				getOwner(mode, crypt_count, buff, &bufSize, (unsigned char**)&buf);
				CryptDecrypt(hSessionKey, 0, true, 0, buf, &bufSize);
				if (!strcmp((char*)buf, "Incorrected path"))
				{
					cout << "Incorrected path. Try again." << endl;
					break;
				};
				int offset = 0;
				char user[MAX_PATH];
				char temp_buf[4];
				char SID_str[100];
				memcpy(user, (char*)buf + offset, MAX_PATH);
				offset += MAX_PATH;
				memcpy(temp_buf, (char*)buf + offset, sizeof(int));
				offset += sizeof(int);
				int str_len = (int&)(*temp_buf);
				memcpy(SID_str, (char*)(buf + offset), 100);
				offset += 100;
				SID_str[str_len] = '\0';
				cout << "User: " << user << " with SID: " << SID_str << endl;
				delete[] buf;
			}
				break;
			case 9://ready
				return;
				break;

			default:
				cout << "Please, enter correct number" << endl;
				break;
			}
			cout << endl;
		}
	}
		RpcExcept(1)
	{
		cerr << "Runtime reported exception " << RpcExceptionCode()
			<< endl;
	}
	RpcEndExcept
}

void clientFunc(char* serverAddress, char* port)
{
	RPC_STATUS status;
	unsigned char* szStringBinding = NULL;

	// Creates a string binding handle.
	// This function is nothing more than a printf.
	// Connection is not done here.
	status = RpcStringBindingCompose(
		NULL, // UUID to bind to.
		(unsigned char*)("ncacn_ip_tcp"), // Use TCP/IP protocol.
		(unsigned char*)serverAddress, // TCP/IP network address to use.
		(unsigned char*)("9000"), // TCP/IP port to use.
		NULL, // Protocol dependent network options to use.
		&szStringBinding); // String binding output.

	if (status)
		exit(status);

	// Validates the format of the string binding handle and converts
	// it to a binding handle.
	// Connection is not done here either.
	status = RpcBindingFromStringBinding(
		szStringBinding, // The string binding to validate.
		&hExample1Binding); // Put the result in the implicit binding
							// handle defined in the IDL file.

	if (status)
		exit(status);

	// operation performing function
	operationPerform();

	// Free the memory allocated by a string.
	status = RpcStringFree(
		&szStringBinding); // String to be freed.

	if (status)
		exit(status);

	// Releases binding handle resources and disconnects from the server.
	status = RpcBindingFree(
		&hExample1Binding); // Frees the implicit binding handle defined in the IDL file.

	if (status)
		exit(status);
}

int main()
{
	SetConsoleCP(1251);
	SetConsoleOutputCP(1251);

	cout << "Enter ip address and port of server (format \"ip-address:port\"): ";
	char port_str[10];
	char ip[30];
	char ipv4[20];
	char serverAddress[20];
	cin.getline(serverAddress, 20, '\n');
	strcpy(ip, strtok(ipv4, ":"));
	strcpy(ipv4, strtok(NULL, ":"));
	strcpy(port_str, strtok(ipv4, " "));
	clientFunc(serverAddress, port_str);
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