#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <libloaderapi.h>

typedef NTSTATUS(__stdcall* _NtQueryInformationProcess)(_In_ HANDLE, _In_ unsigned int, _Out_ PVOID, _In_ ULONG, _Out_ PULONG);

int main()
{

    HMODULE hNtDll = LoadLibraryW(L"ntdll.dll");

    _NtQueryInformationProcess NtQueryInformationProcess = NULL;

    NtQueryInformationProcess = (_NtQueryInformationProcess)GetProcAddress(hNtDll, "NtQueryInformationProcess");
    
    LPSTARTUPINFOA  pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION  pProcessInfo = new PROCESS_INFORMATION();
    LPCSTR processPath = "C:\\Users\\Who\\Desktop\\Books\\Malware\\E-zines\\Gedzac\\Gedzac.Mitosis.Ezine.3\\Gedzac.Mitosis.Ezine.3\\Mitosis3.exe";
    
    BOOL bCreateProcess = CreateProcessA(
                            processPath,
                            0,
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
    }

    LPVOID lpMem;
    char buf;
    DWORD totalRead;

    PROCESS_BASIC_INFORMATION processInfo;
    HANDLE hVictimProcess = pProcessInfo->hProcess;
    NTSTATUS dwStatus = NtQueryInformationProcess(hVictimProcess, ProcessBasicInformation, &processInfo, sizeof(processInfo), 0);

    ReadProcessMemory(hVictimProcess, lpMem, (LPVOID)(&buf), 1, &totalRead);
}

