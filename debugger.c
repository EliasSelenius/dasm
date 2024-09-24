
#include "dasm.h"

int main(int argc, char* argv[]) {

    STARTUPINFO startup_info = {};
    PROCESS_INFORMATION process_info = {};

    startup_info.cb = sizeof(startup_info);

    if (0 == CreateProcessA("tests.exe", null, null, null, false, 0, null, null, &startup_info, &process_info)) {
        printf("CreateProcess failed: %d\n", GetLastError());
        return 1;
    }

    // WaitForSingleObject(process_info.hProcess, INFINITE);


    if (0 == DebugActiveProcess(process_info.dwProcessId)) {
        printf("DebugActiveProcess failed: %d\n", GetLastError());
        CloseHandle(process_info.hProcess);
        CloseHandle(process_info.hThread);
        return 1;
    }


    while (true) {
        DEBUG_EVENT event;
        WaitForDebugEvent(&event, INFINITE);

        switch (event.dwDebugEventCode) {
            case EXCEPTION_DEBUG_EVENT: {
                switch (event.u.Exception.ExceptionRecord.ExceptionCode) {
                    default: printf("Unhandled Exception.\n"); break;
                }
            } break;
            case CREATE_THREAD_DEBUG_EVENT: break;
            case CREATE_PROCESS_DEBUG_EVENT: break;
            case EXIT_THREAD_DEBUG_EVENT: break;
            case EXIT_PROCESS_DEBUG_EVENT: printf("Process exited.\n"); exit(0); break;
            case LOAD_DLL_DEBUG_EVENT: break;
            case UNLOAD_DLL_DEBUG_EVENT: break;
            case OUTPUT_DEBUG_STRING_EVENT: break;
            case RIP_EVENT: break;
        }

        ContinueDebugEvent(event.dwProcessId, event.dwThreadId, DBG_CONTINUE);
    }

    // LoadString()

    return 0;
}