/* PoolSleeping.cpp
Author: The Wover
*/

#include <iostream>
#include <Windows.h>
#include <stacktrace>
#include <wininet.h>

#pragma comment (lib, "Wininet.lib")

#define SLEEP_PERIOD 5000
#define HTTP_SERVER L"www.microsoft.com"

HANDLE hTimer;

void get_work() {
    std::cout << "Getting work from C2 server...\n";

	HINTERNET hSession = InternetOpen(
		L"Mozilla/5.0", // User-Agent
		INTERNET_OPEN_TYPE_PRECONFIG,
		NULL,
		NULL,
		0);

	HINTERNET hConnect = InternetConnect(
		hSession,
		HTTP_SERVER, // HOST
		0,
		L"",
		L"",
		INTERNET_SERVICE_HTTP,
		0,
		0);

	HINTERNET hHttpFile = HttpOpenRequest(
		hConnect,
		L"GET", // METHOD
		L"/",   // URI
		NULL,
		NULL,
		NULL,
		0,
		0);

	while (!HttpSendRequest(hHttpFile, NULL, 0, 0, 0)) {
		printf("HttpSendRequest error : (%lu)\n", GetLastError());

		InternetErrorDlg(
			GetDesktopWindow(),
			hHttpFile,
			ERROR_INTERNET_CLIENT_AUTH_CERT_NEEDED,
			FLAGS_ERROR_UI_FILTER_FOR_ERRORS |
			FLAGS_ERROR_UI_FLAGS_GENERATE_DATA |
			FLAGS_ERROR_UI_FLAGS_CHANGE_OPTIONS,
			NULL);
	}

	DWORD dwFileSize;
	dwFileSize = BUFSIZ;

	char* buffer;
	buffer = new char[dwFileSize + 1];

	while (true) {
		DWORD dwBytesRead;
		BOOL bRead;

		bRead = InternetReadFile(
			hHttpFile,
			buffer,
			dwFileSize + 1,
			&dwBytesRead);

		if (dwBytesRead == 0) break;

		if (!bRead) {
			printf("InternetReadFile error : <%lu>\n", GetLastError());
		}
		else {
			buffer[dwBytesRead] = 0;
			printf("Retrieved %lu data bytes: %s\n", dwBytesRead, buffer);
		}
	}

	InternetCloseHandle(hHttpFile);
	InternetCloseHandle(hConnect);
	InternetCloseHandle(hSession);
    
}

void do_work() {
    std::cout << "Doing all the work that the red team operator tasked for me...\n";
}

void obfuscate() {
    std::cout << "Obfuscating memory before waiting again...\n";
}

void heartbeat(bool fromTimer) {

    if (fromTimer == true)
        std::cout << "Heartbeat from timer...\n";
    else
        std::cout << "Heartbeat from sleeper...\n";

    std::cout << "Current Thread ID: " << GetCurrentThreadId() << "\n";
    std::cout << "Hearbeat callstack:\n" << std::stacktrace::current() << "\n";

    get_work();
    do_work();

    obfuscate();
}

DWORD WINAPI sleeper(_In_ LPVOID lpParameter) {
    while (true) {
        std::cout << "Sleeping for " << SLEEP_PERIOD << " milliseconds...\n";
        Sleep(SLEEP_PERIOD);
        heartbeat(false);
    }
}

// The timer callback must have this function signature
void CALLBACK ticktock(void*, BOOLEAN)
{
    heartbeat(true);
    
}

DWORD WINAPI timer(_In_ LPVOID lpParameter) {
    std::cout << "Setting timer for every " << SLEEP_PERIOD << " milliseconds...\n";
    // create the timer to run the hearbeat
	CreateTimerQueueTimer(&hTimer, NULL, ticktock, NULL, SLEEP_PERIOD, SLEEP_PERIOD, 0);

    // Use WT_TRANSFER_IMPERSONATION to ensure any impersonation we may have used in our current thread is persisted
    //CreateTimerQueueTimer(&hTimer, NULL, ticktock, NULL, SLEEP_PERIOD, SLEEP_PERIOD, WT_TRANSFER_IMPERSONATION);

    // Exit the thread that sets up the timer so that we can see that the heartbeat continues even without a sleeping thread
    ExitThread(0);

    // You could later delete the timer with:
    // DeleteTimerQueueTimer(NULL, hTimer, NULL);
}

int main(int argc, char* argv[])
{
    std::cout << "Process ID: " << GetCurrentProcessId() << "\n";

    if (argc > 1) {
        if (*argv[1] == '0')
            // Run in its own thread so we can watch how it behaves
            CreateThread(NULL, 0, &sleeper, NULL, 0, NULL);
        else if (*argv[1] == '1')
            // Run in its own thread so we can watch how it behaves
            CreateThread(NULL, 0, &timer, NULL, 0, NULL);
        else
            std::cout << "Invalid option. Please run with 'PoolSleeping.exe 0' to run demo with a sleeping thread or 'PoolSleeping.exe 1' to run with a timer and threadpool.\n";
    }
    else
        std::cout << "Invalid option. Please run with 'PoolSleeping.exe 0' to run demo with a sleeping thread or 'PoolSleeping.exe 1' to run with a timer and threadpool.\n";

    // pause so you may read the results
    system("pause");
}