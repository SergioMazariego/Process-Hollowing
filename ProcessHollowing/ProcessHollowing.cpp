#include <windows.h>
#include <stdio.h>
#include <winternl.h>
#include <libloaderapi.h>

int main()
{
    LPSTARTUPINFOA  pStartupInfo = new STARTUPINFOA();
    LPPROCESS_INFORMATION  pProcessInfo = new PROCESS_INFORMATION();
    
    BOOL bCreateProcess = CreateProcessA(
                            "C:\\Users\\Who\\Desktop\\Books\\Malware\\E-zines\\Gedzac\\Gedzac.Mitosis.Ezine.3\\Gedzac.Mitosis.Ezine.3\\Mitosis3.exe",
                            0,
                            0,
                            0,
                            0,
                            CREATE_SUSPENDED,
                            0,
                            0,
                            pStartupInfo, //A pointer to a STARTUPINFO or STARTUPINFOEX structure.
                            pProcessInfo //A pointer to a PROCESS_INFORMATION structure that receives identification information about the new process.
                        );

    if (bCreateProcess) 
    {
        printf("Process Created");
    }
    else
    {
        printf("Error creating process");
    }

    PROCESS_BASIC_INFORMATION processInfo;
    NTSTATUS dwStatus = NtQueryInformationProcess(pProcessInfo->hProcess, ProcessBasicInformation, &processInfo, sizeof(processInfo), 0);

    if (dwStatus >= 0)
    {
        printf("NtQueryInformationProcess succeded");
    }
}

