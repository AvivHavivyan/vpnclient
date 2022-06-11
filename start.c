

#include <stdlib.h>
#include <unistd.h>
#include <stdio.h>

// a wrapper program for the client program that checks if it's running,
// if it isn't it turns off the proxy settings.
int main() {
    // command that starts the client program
    system("start vpnclient.exe");
    int ret_value = 0;
    while (ret_value == 0) { // look for the program in the list of running programs
        ret_value = system("tasklist /fo list | find /c \"vpnclient.exe\"");
    }
    while (1) {
        ret_value = system("tasklist /fo list | find /c \"vpnclient.exe\"");
        if (ret_value>>8 == 0) { // if the program is not running turn off the proxy settings.
            system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v \"ProxyEnable\" /t REG_DWORD /d \"0\" /f");
            printf("Closing proxy...");
            return 0;
        }
        sleep(2000); // wait for 2 secomds between each iteration
    }

}