# WinOsInfo-collecting-system
Client-Server system based on Winsock. Main logic of work include collecting from clients Windows OS information such as:
- OS type and version
- Current Time
- Time since launch
- Info about using memory
- Info about system disks
- Info about ACL and Owners for files, directories and registry key

All information collects on clients using WinAPI functions and sent encrypted on server. Encryption is implemented using CryptoAPI.
Server is statefull and use the I/O Completion Ports mechanism to connect with clients.
