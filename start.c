//
// Created by Aviv on 13/03/2022.
//

#include <stdlib.h>
#include <process.h>
#include <unistd.h>
#include <stdio.h>

int main() {
    system("start vpnclient.exe");
    int ret_value = 0;
    while (ret_value == 0) {
        ret_value = system("tasklist /fo list | find /c \"vpnclient.exe\"");
    }
    while (1) {
        ret_value = system("tasklist /fo list | find /c \"vpnclient.exe\"");
        if (ret_value>>8 == 0) {
            system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v \"ProxyEnable\" /t REG_DWORD /d \"0\" /f");
            printf("Closing proxy...");
            return 0;
        }
        sleep(2000);
    }

}