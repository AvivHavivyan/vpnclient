//
// Created by Aviv on 27/01/2022.
//

#include <stdio.h>
#include <ws2tcpip.h>
#include <unistd.h>
#include <stdbool.h>
#include <process.h>
#define DEFAULT_PORT "27015"
#define LISTEN_PORT "5102"
#define DEFAULT_BUFLEN 512

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

void WSAAPI freeaddrinfo( struct addrinfo* );

int WSAAPI getaddrinfo( const char*, const char*, const struct addrinfo*,
                        struct addrinfo** );

int WSAAPI getnameinfo( const struct sockaddr*, socklen_t, char*, DWORD,
                        char*, DWORD, int );

SOCKET connecttoserver( struct addrinfo * result) {
    int iResult;

// Create a SOCKET for connecting to server
    SOCKET ConnectSocket = socket(result->ai_family, result->ai_socktype,result->ai_protocol);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Connect to server.
    iResult = connect(ConnectSocket, result->ai_addr, (int)result->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    return ConnectSocket;
}

int thread(SOCKET * ProxySocket, struct addrinfo * listen_addr, struct addrinfo * ptr, struct addrinfo * result) {
    int iResult = 0;
    char sendbuf[2048];
    char recvbuf[DEFAULT_BUFLEN];

//    conn:

    while (true) {
        iResult = 0;

        // Loop until the message is sent.
        bool sent = false;

        // Resetting buffers
        memset(sendbuf, 0, sizeof(sendbuf));
        memset(recvbuf, 0, sizeof(recvbuf));

        // Intercept http requests
        recv(*ProxySocket, sendbuf, 2048, 0);

        //filter out https requests (e.g. CONNECT)
        // TODO: (improve filtering - to be within the first word.)
        if (strstr(sendbuf, "CONNECT")) {
            break;
        }

        printf(sendbuf);

        SOCKET VpnSocket = connecttoserver(result);

        int contentLength = strlen(sendbuf);
        int originalContentLength = contentLength;
        char * message = sendbuf;
        sent = false;
        int startIndex = 0;
        int endIndex = DEFAULT_BUFLEN - 1;
        u_long netContentLength = 0;
        netContentLength = htonl(contentLength);
        send(VpnSocket, &netContentLength, 4, 0);
        while (!sent) {
            if (contentLength < DEFAULT_BUFLEN) {
                endIndex = originalContentLength;
            }
            char curMessage[endIndex];
            memset(curMessage, 0, DEFAULT_BUFLEN);
            strncpy(curMessage, &message[startIndex], endIndex - startIndex);

            //Current batch length.
            if (contentLength > DEFAULT_BUFLEN) {
                iResult = send(VpnSocket, curMessage, DEFAULT_BUFLEN, 0);
                startIndex = endIndex;
                endIndex = endIndex + DEFAULT_BUFLEN;
            }
            else if (contentLength <= DEFAULT_BUFLEN) {
                iResult = send(VpnSocket, curMessage, strlen(curMessage), 0);
                sent = true;
            }
            contentLength -= DEFAULT_BUFLEN;

            if (iResult == SOCKET_ERROR) {
                printf("send failed: %d\n", WSAGetLastError());
                closesocket(VpnSocket);
                WSACleanup();
                return 1;
            }
        }

        // TODO: add option to handle message len of 0.

        bool received = false;
        netContentLength = 0;
        iResult = 0;
        while (iResult == 0) {
            iResult = recv(VpnSocket, &netContentLength, 4, 0);
        }
        contentLength = ntohl(netContentLength);
        char fullmsg[contentLength];
        memset(fullmsg, 0, strlen(fullmsg));

        if (contentLength == 0) {
            printf("Connection to vpn server terminated unexpectedly.");
            closesocket(VpnSocket);
            WSACleanup();
            return -1;
        }


        while (!received) {
            char msg[DEFAULT_BUFLEN];

            memset(msg, 0, DEFAULT_BUFLEN);

            if (contentLength < DEFAULT_BUFLEN) {
                iResult = recv(VpnSocket, msg, contentLength, 0);
                strcat(fullmsg, msg);
                printf(fullmsg);
                send(*ProxySocket, fullmsg, strlen(fullmsg), 0);
                closesocket(*ProxySocket);
                closesocket(VpnSocket);
                return 0;
            } else {
                iResult = recv(VpnSocket, msg, DEFAULT_BUFLEN, 0);
                strcat(fullmsg, msg);
                contentLength -= DEFAULT_BUFLEN;
            }
            if (iResult == SOCKET_ERROR) {
                printf("Connection closed\n");
                WSACleanup();
                return 1;
            }
            else if (iResult < 0)
                printf("recv failed: %d\n", WSAGetLastError());
        }

        // TODO: send response to back to the proxy port.

    }

}

// TODO: add multithreading

int main() {
    WSADATA wsaData;
    int iResult;

// Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2,2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    struct addrinfo *result = NULL,
            *ptr = NULL,
            *listen_addr = NULL,
            hints;

    // reset the memory of hints and set values for each of the following parameters: internet protocol v4, tcp
    ZeroMemory(&hints, sizeof(hints) );
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;

    // Resolve the server address and port
    iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    iResult = getaddrinfo("127.0.0.1", LISTEN_PORT, &hints, &listen_addr);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }
    SOCKET ListenSocket = INVALID_SOCKET;

    SOCKET ConnectSocket = INVALID_SOCKET;

// Attempt to connect to the first address returned by
// the call to getaddrinfo

    ListenSocket = socket(listen_addr->ai_family, listen_addr->ai_socktype, listen_addr->ai_protocol);

    system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v \"ProxyServer\" /t REG_SZ /d \"127.0.0.1:5102\" /f");
    system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v \"ProxyEnable\" /t REG_DWORD /d \"1\" /f");

    iResult = bind(ListenSocket, listen_addr->ai_addr, (int)listen_addr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        return 1;
    }
    //TODO: ping the server every once in a while.

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    while (1) {
        printf("Listening... ");
        if (listen(ListenSocket, SOMAXCONN) == SOCKET_ERROR) {
            printf("Listen failed with error: %d\n", WSAGetLastError());
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        }

        SOCKET ProxySocket = accept(ListenSocket, NULL, NULL);

        if (ProxySocket == INVALID_SOCKET) {
            closesocket(ListenSocket);
            WSACleanup();
            return 1;
        } else {
            printf("Connected. \n");
        }
        thread( &ProxySocket, listen_addr, ptr, result);
    }
#pragma clang diagnostic pop

}
