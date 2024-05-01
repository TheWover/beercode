// Demonstrates use of NtQuerySystemInformation and SystemProcessIdInformation to get the image name of a process without opening a process handle
// Author: TheWover
//

#include <iostream>
#include <string>
#include "ntdefs.h"

bool demoSystemProcessIdInformation(ULONGLONG PID)
{
    NTSTATUS status;

    //Resolve the address of NtQuerySystemInformation
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    // Allocate enough memory
    // 254 is the maximum length in bytes of the image path
    void *allocBuffer = LocalAlloc(LMEM_FIXED | LMEM_ZEROINIT, 254);
    if (!allocBuffer)
        return false;

    // We will query the SystemProcessIdInformation class, which provides the Image Name of a process given its PID.
    // It is also possible to enumerate all processes and get their PID and Image name using this class, but for simplicity's sake we are requesting just one process's info.
    // The SystemProcessIdInformation class requires us to pass in a struct of the type SYSTEM_PROCESS_ID_INFORMATION
    // Now we create that strcut type and add our PID and buffer info
    SYSTEM_PROCESS_ID_INFORMATION outputSPII = { 0 };
    outputSPII.ProcessId = PID;
    outputSPII.ImageName.MaximumLength = 254;
    outputSPII.ImageName.Buffer = (PWSTR) allocBuffer;

    // Run the query and capture the NTSTATUS result in case there is an error.
    status = NtQuerySystemInformation(SystemProcessIdInformation, &outputSPII, sizeof(outputSPII), 0);

    printf("NTSTATUS: %ld \n", status);
    if (status == 0)
        printf("Process %lld has an image path of: %wZ\n", PID, &outputSPII.ImageName);
    else
    {
        LocalFree(allocBuffer);
        return false;
    }
    
    LocalFree(allocBuffer);

    return true;
}

bool IsPIDWow64(ULONGLONG PId)
{
    // Get the path of the process's executable image

    // use SystemProcessIdInformation to get the path of the process

    // check the PE headers to determine the process's architecture 

    return 0;
}


bool demoSystemProcessInformation(bool full)
{
    NTSTATUS status;
    PVOID buffer;
    PSYSTEM_PROCESS_INFORMATION spi;
    ULONG ReturnLength;
    HMODULE ntdll = GetModuleHandleA("ntdll.dll");

    //Resolve the address of NtQuerySystemInformation
    _NtQuerySystemInformation NtQuerySystemInformation = (_NtQuerySystemInformation)GetProcAddress(ntdll, "NtQuerySystemInformation");

    // Each variant of this information class includes some extra information:
        // SystemProcessInformation: No extra info
        // SystemExtendedProcessinformation: SYSTEM_EXTENDED_THREAD_INFORMATION Threads[1]
        // SystemFullProcessInformation: SYSTEM_EXTENDED_THREAD_INFORMATION + SYSTEM_PROCESS_INFORMATION_EXTENSION

        // SystemFullProcessInformation only works as admin
    if (full == false)
        status = NtQuerySystemInformation(SystemExtendedProcessInformation, NULL, 0, &ReturnLength);
    else
        status = NtQuerySystemInformation(SystemFullProcessInformation, NULL, 0, &ReturnLength);
    
    // Allocate enough memory
    buffer = VirtualAlloc(NULL, ReturnLength, MEM_COMMIT, PAGE_READWRITE);
    if (!buffer)
    {
        printf("Error allocating memory: %d\n", GetLastError());
        printf("NTSTATUS from initial NtQuerySystemInformation call: 0x%X \n", status);
        return false;
    }

    spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

    // Now that we have the memory allocated, we call it again to get the info
    if (full == false)
        status = NtQuerySystemInformation(SystemExtendedProcessInformation, spi, ReturnLength, NULL);
    else
        status = NtQuerySystemInformation(SystemFullProcessInformation, spi, ReturnLength, NULL);

    if (!NT_SUCCESS(status))
    {
        printf("NTSTATUS: 0x%X \n", status);
        VirtualFree(buffer, 0, MEM_RELEASE);
        return false;
    }

    // Loop over the linked list of processes until we reach the last entry.
    while (spi->NextEntryOffset)
    {
        printf("PID: %lld\n", (ULONGLONG)spi->UniqueProcessId);

        // This only contains the filename of the binary, not the full path.
        // For the full path you can call NtQuerySystemInformation with SystemProcessIdInformation info class, passing in the PID
        printf("Image Name : %wZ\n", spi->ImageName);

        if (spi->UniqueProcessId)
            printf("\tPPID: %lld\n", (ULONGLONG)spi->InheritedFromUniqueProcessId);

        printf("\tSession: %lld\n", (ULONGLONG)spi->SessionId);

        // If we used SystemFullProcessInformation then we can get the username using LookupAccountSid
        if (full == true)
        {
            CHAR namebuffer[1024] = { 0 };

            PSYSTEM_PROCESS_INFORMATION_EXTENSION process_ext = (PSYSTEM_PROCESS_INFORMATION_EXTENSION)(((PBYTE)spi->Threads) + (sizeof(SYSTEM_EXTENDED_THREAD_INFORMATION) * spi->NumberOfThreads));

            PSID pSID = (PSID)(((PBYTE)process_ext) + process_ext->UserSidOffset);

            SID_NAME_USE sidtype = SidTypeUnknown;
            DWORD account_length = 0;
            DWORD domain_length = 0;
            // Get the length of the username and domain
            LookupAccountSidA(NULL, pSID, NULL, &account_length, NULL, &domain_length, &sidtype);
            // Not that the username is inserted after the domain and we add the \ in between them afterwards
            LookupAccountSidA(NULL, pSID, namebuffer + domain_length, &account_length, namebuffer, &domain_length, &sidtype);
            if (domain_length > 0)
                namebuffer[domain_length] = '\\';

            printf("Username: %s\n", namebuffer);
        }

        printf("\tThreads: %ld\n", spi->NumberOfThreads);

        for (unsigned int i = 0; i < spi->NumberOfThreads; i++)
        {
            PSYSTEM_THREAD_INFORMATION sti = (PSYSTEM_THREAD_INFORMATION)((LPBYTE)(spi->Threads) + i * sizeof(SYSTEM_THREAD_INFORMATION));

            if (sti->StartAddress)
                // You can attempt to determine whether the process is 64-bit or not by checking ifthe SYSTEM_EXTENDED_THREAD_INFORMATION.Win32StartAddress is over 0xffffffff
                // However, that approach is not 100% reliable. A better approach is to check the PE headers of the executble file to determine its architecture.
                
                // You can also get other information from the thread info, such as ThreadState and WaitReason
                
                printf("\t\tThread start address: %p\n", sti->StartAddress);
        }

        spi = (PSYSTEM_PROCESS_INFORMATION)((LPBYTE)spi + spi->NextEntryOffset); // Calculate the address of the next entry.
    }

    VirtualFree(buffer, 0, MEM_RELEASE);

    return true;
}


int main(int argc, char* argv[])
{
    /*
    if (argc > 1)
    {
        if (demoSystemProcessIdInformation(std::stoll(argv[1])) == false)
            printf("Error: Failed to query process %s", argv[1]);
    }
    else
        printf("Error: Please provide a PID as an argument.\n");    
    */

    if (argc > 1)
    {
        bool success = false;
        if (*argv[1] == '0')
            success = demoSystemProcessInformation(false);
        else if (*argv[1] == '1')
            success = demoSystemProcessInformation(true);
        else
            printf("Error: Please provide an argument '0' for Extended info and '1' for Full info.\n");

        if (success == false)
            printf("Error: Execution failed!");
    }
    else
        printf("Error: Please provide an argument '0' for Extended info and '1' for Full info.\n");
}
