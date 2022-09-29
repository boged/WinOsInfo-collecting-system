#define _WINSOCK_DEPRECATED_NO_WARNINGS
#define _CRT_SECURE_NO_WARNINGS
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

#define MAX_PATH 260

using namespace std;
//Глобальные переменные
int port_int;
char port_str[10];
char ip[30];
char ipv4[20];
HCRYPTKEY sessionKey = NULL;
void init_wsa()
{
	WSADATA wd;
	if (WSAStartup(MAKEWORD(2, 2), &wd) == 0)
	{
		printf("WSAStartup is ok\n");
	}
	else
	{
		printf("WSAStartup error %d\n", WSAGetLastError());
		exit(0);
	}
}
void separate_ip()
{
	strcpy(ip, strtok(ipv4, ":"));
	strcpy(ipv4, strtok(NULL, ":"));
	strcpy(port_str, strtok(ipv4, " "));
	port_int = atoi(port_str);
	//printf("%s\n%s - str\n%d - int", ip, port_str, port_int);
}
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

void crypt_transfer(int sock)
{
	//CRYPTOAPI
	HCRYPTPROV hprov;
	HCRYPTKEY hPublicKey;
	//Создание контейнера ключей
	int f1 = CryptAcquireContext(&hprov, NULL, NULL, PROV_RSA_FULL, CRYPT_VERIFYCONTEXT);
	//  std::cout << "Cryptographic provider initialized" << std::endl;
	//Создаем публичный/приватный ключ

	int f2 = CryptGenKey(hprov, AT_KEYEXCHANGE, CRYPT_ARCHIVABLE | CRYPT_EXPORTABLE, &hPublicKey);
	//  std::cout << "Public key is generated" << std::endl;
	//Готовим публичный ключ к отправке, узнаем размер массива на отпраку
	DWORD count = 0;
	int f3 = CryptExportKey(hPublicKey, NULL, PUBLICKEYBLOB, NULL, NULL, &count);
	BYTE* data = (BYTE*)malloc(count * sizeof(BYTE));
	//Отправляем ключ шифрования
	int f4 = CryptExportKey(hPublicKey, NULL, PUBLICKEYBLOB, NULL, data, &count);
	//  std::cout << "Public's export completed" << std::endl;
	//Отправляем публичный ключ
	send(sock, (const char*)data, count, 0);

	unsigned char buf[512];
	int f5 = recv(sock, (char*)buf, 512, 0);

	DWORD len_recv = f5;
	f5 = CryptDecrypt(hPublicKey, NULL, TRUE, NULL, buf, &len_recv);
	HCRYPTPROV server;
	int f6 = CryptAcquireContext(&server, NULL, MS_ENH_RSA_AES_PROV, PROV_RSA_AES, CRYPT_VERIFYCONTEXT | CRYPT_NEWKEYSET);
	int f7 = CryptImportKey(server, buf, count, 0, 0, &sessionKey);

	free(data);
}

int main(int argc, char* argv[])
{
	//Проверяем аргументы командной строки
	if (argv[1] != NULL)
		strcpy(ipv4, argv[1]);
	else
	{
		std::cout << "Enter ip address and port of server (format \"ip-address:port\"): ";
		char serverAddress[20];
		std::cin.getline(serverAddress, 20, '\n');
		strcpy(ipv4, serverAddress);
	}
	separate_ip();
	//Включаем wsa
	init_wsa();
	//Создаем сокет, через который будем отправлять запросы серверу
	int sock = socket(AF_INET, SOCK_STREAM, 0);
	if (sock < 0)
	{
		printf("Socket error %d\n", GetLastError());
		exit(0);
	}
	struct sockaddr_in addr;
	memset(&addr, 0, sizeof(addr));
	addr.sin_family = AF_INET;
	addr.sin_port = htons(port_int);
	addr.sin_addr.s_addr = inet_addr(ip);

	if (connect(sock, (struct sockaddr*) & addr, sizeof(addr)) < 0)
	{
		printf("Connect error %d\n", GetLastError());
		exit(0);
	}
	printf("Connected to %s:%d\n", ip, port_int);
	print_menu();
	int buffer;

	crypt_transfer(sock);

	while (1)
	{
		std::cout << "Enter command: ";
		while (scanf_s(" %d", &buffer) != 1)
		{
			system("cls");
			printf("Incorrect input, try entering a number!\n");
			print_menu();
			while (getchar() != '\n');
		}
		switch (buffer)
		{
		case 1:
		{
			char buf_send[] = "OS";
			send(sock, buf_send, 2, 0);
			BYTE buf_recv[512];
			memset(&buf_recv, 0, sizeof(buf_recv));
			DWORD rcv = recv(sock, (char*)buf_recv, 512, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &rcv);
			char buf_print[512];
			memcpy(buf_print, buf_recv, 512);
			buf_print[rcv] = '\0';
			cout << "OS Version is " << buf_print << endl;
			break;
		}
		case 2://Готово и расшифровано
		{
			//Отправляем запрос на получение текущего времени
			char buf_send[] = "CurTime";
			send(sock, buf_send, 7, 0);
			BYTE buf_recv[512];
			memset(&buf_recv, 0, sizeof(buf_recv));
			DWORD rcv = recv(sock, (char*)buf_recv, 512, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &rcv);
			WORD hour, minute, second, day, month, year;
			char temp_buf[4];
			int offset = 0;
			int size = sizeof(WORD);
			memcpy(temp_buf, buf_recv + offset, size);
			offset += size;
			hour = (WORD&)*temp_buf;
			memcpy(temp_buf, buf_recv + offset, size);
			offset += size;
			minute = (WORD&)*temp_buf;
			memcpy(temp_buf, buf_recv + offset, size);
			offset += size;
			second = (WORD&)*temp_buf;
			memcpy(temp_buf, buf_recv + offset, size);
			offset += size;
			day = (WORD&)*temp_buf;
			memcpy(temp_buf, buf_recv + offset, size);
			offset += size;
			month = (WORD&)*temp_buf;
			memcpy(temp_buf, buf_recv + offset, size);
			year = (WORD&)*temp_buf;
			cout << "Current time and date: " << hour << ':' << minute << ':' << second << " " << day << '.' << month << '.' << year << endl;
			break;
		}
		case 3://Готово и расшифровано
		{
			//Отправляем запрос на получение времени с момента запуска
			char buf_send[] = "TimeLaunch";
			send(sock, buf_send, 10, 0);
			int hh, mm, ss;

			BYTE buf_recv[512];
			memset(&buf_recv, 0, sizeof(buf_recv));
			DWORD rcv = recv(sock, (char*)buf_recv, 512, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &rcv);
			char temp_buf[4];
			memcpy(temp_buf, buf_recv, 4);
			unsigned long hour = (unsigned long&)*temp_buf;
			memcpy(temp_buf, buf_recv + 4, 4);
			unsigned long minute = (unsigned long&)*temp_buf;
			memcpy(temp_buf, buf_recv + 8, 4);
			unsigned long second = (unsigned long&)*temp_buf;
			cout << "Time since launching: " << hour << ':' << minute << ':' << second << endl;
			break;
		}
		case 4://Готов и расшифровано
		{
			//Отправляем запрос про память
			char buf_send[] = "Memory";
			send(sock, buf_send, 6, 0);

			unsigned char buf_recv[4096];
			memset(&buf_recv, 0, sizeof(buf_recv));
			DWORD rcv = recv(sock, (char*)buf_recv, 4096, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &rcv);

			char temp_buf[4];
			int size = sizeof(DWORD);
			int offset = 0;
			memcpy(temp_buf, buf_recv + offset, size);
			DWORD MemoryLoad = (int&)*temp_buf;
			offset += size;

			memcpy(temp_buf, buf_recv + offset, size);
			DWORD TotalPhys = (int&)*temp_buf;
			offset += size;

			memcpy(temp_buf, buf_recv + offset, size);
			DWORD AvailPhys = (int&)*temp_buf;
			offset += size;

			memcpy(temp_buf, buf_recv + offset, size);
			DWORD TotalPF = (int&)*temp_buf;
			offset += size;

			memcpy(temp_buf, buf_recv + offset, size);
			DWORD AvailPF = (int&)*temp_buf;
			offset += size;

			memcpy(temp_buf, buf_recv + offset, size);
			DWORD TotalVirtual = (int&)*temp_buf;
			offset += size;

			memcpy(temp_buf, buf_recv + offset, size);
			DWORD AvailVirtual = (int&)*temp_buf;

			cout << "Memory load: " << MemoryLoad << "%" << endl;
			cout << "Total amount of phys memory: " << TotalPhys << " Kbytes" << endl;
			cout << "Available phys memory: " << AvailPhys << " Kbytes" << endl;
			cout << "Max amount of memory for programms: " << TotalPF << " Kbytes" << endl;
			cout << "Available amount of memory for programms: " << AvailPF << " Kbytes" << endl;
			cout << "Max amount of virtual memory: " << TotalVirtual << " Kbytes" << endl;
			cout << "Availbale amount of virtual memory: " << AvailVirtual << " Kbytes" << endl;
			break;
		}
		case 5://Готово и расшифровано
		{
			char buf_send[] = "Disk";
			send(sock, buf_send, 4, 0);
			BYTE buf_recv[512];
			memset(&buf_recv, 0, sizeof(buf_recv));
			DWORD rcv = recv(sock, (char*)buf_recv, 512, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &rcv);
			int num = rcv / 4;
			char buf_litera[5];
			char buf_num;
			for (int i = 0; i < num; i++)
			{
				memset(&buf_litera, 0, 5);
				buf_num = 0;
				memcpy(buf_litera, buf_recv + i * 4, 3);
				buf_litera[4] = '\0';
				buf_num = buf_recv[i * 4 + 3];
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
			break;
		}
		case 6://Готово и расшифровано
		{
			char buf_send[] = "Free";
			send(sock, buf_send, 4, 0);
			BYTE buf_recv[512];
			memset(&buf_recv, 0, sizeof(buf_recv));
			DWORD len = recv(sock, (char*)buf_recv, 512, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &len);
			int num = len / 7;
			int offset = 0;
			for (int i = 0; i < num; i++)
			{
				char buf_litera[4];
				memcpy(buf_litera, buf_recv + offset, 3);
				buf_litera[3] = '\0';
				offset += 3;
				char buf_size[4];
				memcpy(buf_size, buf_recv + offset, 4);
				offset += 4;
				int disk_size = (int&)(*buf_size);
				cout << "Disk " << buf_litera << " has " << disk_size << " GB of free space" << endl;
			}
			break;
		}
		case 7://Готово и расшифровано
		{
			setlocale(LC_ALL, "Russian");
			char buf_send[500] = "ACL";
			char fileway[300];
			puts("Enter the path to file:");
			scanf("%s", fileway);
			puts("If it's file/dir enter 1, key - 2");
			char buf_num;
			std::cin >> buf_num;
			buf_send[3] = buf_num;
			strcat(buf_send, fileway);
			send(sock, buf_send, strlen(buf_send), 0);

			//DWORD size = 4 + 8 * (MAX_PATH + 4 + 4 + 100);
			BYTE buf_recv[3684];
			memset(&buf_recv, 0, 3684);
			DWORD len = recv(sock, (char*)buf_recv, 3684, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &len);

			if (!strcmp((char*)buf_recv, "Incorrected path"))
			{
				std::cout << "Incorrected path. Try again." << std::endl;
				break;
			};

			char temp_buf[4];
			int offset = 0;
			memcpy(temp_buf, buf_recv + offset, sizeof(int));
			offset += sizeof(int);
			int ace_count = (int&)*temp_buf;

			char user[MAX_PATH];
			char SID_str[101];

			for (int i = 0; i < ace_count; i++)
			{
				memcpy(user, buf_recv + offset, MAX_PATH);
				offset += MAX_PATH;

				//memcpy(temp_buf, buf_recv + offset, sizeof(int));
				//offset += sizeof(int);
				//int AceType = (int&)*temp_buf;
				//const char *AceTypeStr;
				//if (AceType) AceTypeStr = "ACCESS_ALLOWED_ACE_TYPE";
				//else AceTypeStr = "ACCESS_DENIED_ACE_TYPE";

				memcpy(temp_buf, buf_recv + offset, sizeof(int));
				offset += sizeof(int);
				int mask = (int&)*temp_buf;

				memcpy(temp_buf, buf_recv + offset, sizeof(int));
				offset += sizeof(int);
				int sid_len = (int&)*temp_buf;

				memcpy(SID_str, buf_recv + offset, 100);
				offset += 100;
				SID_str[sid_len] = '\0';
				std::cout << "User: " << user << " with SID: " << SID_str << '\n'
					//<< "Ace Type: " << AceTypeStr << '\n'
					<< "Access rights:\n";
				if (buf_num == '1')
				{
					if (mask & FILE_READ_DATA)
						std::cout << "\tFILE_READ_DATA" << std::endl;
					if (mask & FILE_WRITE_DATA) // or directory FILE_ADD_FILE (0x0002)
						std::cout << "\tFILE_WRITE_DATA" << std::endl;
					if (mask & FILE_APPEND_DATA) // or directory FILE_ADD_SUBDIRECTORY (0x0004)
						std::cout << "\tFILE_APPEND_DATA" << std::endl;
					if (mask & FILE_READ_EA)
						std::cout << "\tFILE_READ_EA" << std::endl;
					if (mask & FILE_WRITE_EA)
						std::cout << "\tFILE_WRITE_EA" << std::endl;
					if (mask & FILE_EXECUTE) // or directory FILE_TRAVERSE (0x0020)
						std::cout << "\tFILE_EXECUTE" << std::endl;
					if (mask & FILE_DELETE_CHILD) // only for directory
						std::cout << "\tFILE_DELETE_CHILD" << std::endl;
					if (mask & FILE_READ_ATTRIBUTES)
						std::cout << "\tFILE_READ_ATTRIBUTES" << std::endl;
					if (mask & FILE_WRITE_ATTRIBUTES)
						std::cout << "\tFILE_WRITE_ATTRIBUTES" << std::endl;
				}
				else
				{
					if (mask & KEY_QUERY_VALUE)
						std::cout << "\tKEY_QUERY_VALUE" << std::endl;
					if (mask & KEY_SET_VALUE)
						std::cout << "\tKEY_SET_VALUE" << std::endl;
					if (mask & KEY_CREATE_SUB_KEY)
						std::cout << "\tKEY_CREATE_SUB_KEY" << std::endl;
					if (mask & KEY_ENUMERATE_SUB_KEYS)
						std::cout << "\tKEY_ENUMERATE_SUB_KEYS " << std::endl;
					if (mask & KEY_NOTIFY)
						std::cout << "\tKEY_NOTIFY" << std::endl;
					if (mask & KEY_CREATE_LINK)
						std::cout << "\tKEY_CREATE_LINK " << std::endl;
					if (mask & KEY_WOW64_32KEY)
						std::cout << "\tKEY_WOW64_32KEY" << std::endl;
					if (mask & KEY_WOW64_64KEY)
						std::cout << "\tKEY_WOW64_64KEY " << std::endl;
					if (mask & KEY_WOW64_RES)
						std::cout << "\tKEY_WOW64_RES" << std::endl;
					if (mask & KEY_READ)
						std::cout << "\tKEY_READ" << std::endl;
					if (mask & KEY_WRITE)
						std::cout << "\tKEY_WRITE" << std::endl;
					if (mask & KEY_EXECUTE)
						std::cout << "\tKEY_EXECUTE" << std::endl;
					if (mask & KEY_ALL_ACCESS)
						std::cout << "\tKEY_ALL_ACCESS" << std::endl;
				}
				std::cout << "Standard access types:" << std::endl;
				if (mask & DELETE)
					std::cout << "\tDELETE" << std::endl;
				if (mask & READ_CONTROL)
					std::cout << "\tREAD_CONTROL" << std::endl;
				if (mask & WRITE_DAC)
					std::cout << "\tWRITE_DAC" << std::endl;
				if (mask & WRITE_OWNER)
					std::cout << "\tWRITE_OWNER" << std::endl;
				if (mask & SYNCHRONIZE)
					std::cout << "\tSYNCHRONIZE" << std::endl;
				if (mask & GENERIC_READ)
					std::cout << "\tGENERIC_READ" << std::endl;
				if (mask & GENERIC_WRITE)
					std::cout << "\tGENERIC_WRITE" << std::endl;
				if (mask & GENERIC_EXECUTE)
					std::cout << "\tGENERIC_EXECUTE" << std::endl;
				if (mask & GENERIC_ALL)
					std::cout << "\tGENERIC_ALL" << std::endl;
				std::cout << '\n';
			}
			break;
		}
		case 8://Готово и расшифровано
		{
			setlocale(LC_ALL, "Russian");
			char buf_send[500] = "Own";
			char fileway[300];
			puts("Enter the path to file:");
			scanf("%s", fileway);
			puts("If it's file/dir enter 1, key - 2");
			char buf_num;
			std::cin >> buf_num;
			buf_send[3] = buf_num;
			strcat(buf_send, fileway);
			send(sock, buf_send, strlen(buf_send), 0);

			BYTE buf_recv[364];
			memset(&buf_recv, 0, 364);
			DWORD len = recv(sock, (char*)buf_recv, 3684, 0);
			int f1 = CryptDecrypt(sessionKey, NULL, TRUE, NULL, buf_recv, &len);

			if (!strcmp((char*)buf_recv, "Incorrected path"))
			{
				std::cout << "Incorrected path. Try again." << std::endl;
				break;
			};

			int offset = 0;
			char user[MAX_PATH];
			char temp_buf[4];
			char SID_str[100];

			memcpy(user, (char*)buf_recv + offset, MAX_PATH);
			offset += MAX_PATH;

			memcpy(temp_buf, (char*)buf_recv + offset, sizeof(int));
			offset += sizeof(int);
			int str_len = (int&)(*temp_buf);

			memcpy(SID_str, (char*)(buf_recv + offset), 100);
			offset += 100;
			SID_str[str_len] = '\0';

			cout << "User: " << user << " with SID: " << SID_str << '\n';
			break;
		}
		case 9:
		{
			exit(0);
		}
		default:
		{
			printf("Wrong number, try again!\n");
			break;
		}
		}
	}
	cout << endl;
	return 0;
}