//
// Created by Aviv on 27/01/2022.
//

#include <stdio.h>
#include <ws2tcpip.h>
#include <unistd.h>
#include <stdbool.h>
#define DEFAULT_PORT "27015"
#define DEFAULT_BUFLEN 512

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

void WSAAPI freeaddrinfo( struct addrinfo* );

int WSAAPI getaddrinfo( const char*, const char*, const struct addrinfo*,
                        struct addrinfo** );

int WSAAPI getnameinfo( const struct sockaddr*, socklen_t, char*, DWORD,
                        char*, DWORD, int );

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

    SOCKET ConnectSocket = INVALID_SOCKET;
// Attempt to connect to the first address returned by
// the call to getaddrinfo
    ptr=result;

// Create a SOCKET for connecting to server
    ConnectSocket = socket(ptr->ai_family, ptr->ai_socktype,
                           ptr->ai_protocol);
    if (ConnectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        freeaddrinfo(result);
        WSACleanup();
        return 1;
    }

    // Connect to server.
    iResult = connect( ConnectSocket, ptr->ai_addr, (int)ptr->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        closesocket(ConnectSocket);
        ConnectSocket = INVALID_SOCKET;
    }

    freeaddrinfo(result);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Unable to connect to server!\n");
        WSACleanup();
        return 1;
    }
    int recvbuflen = DEFAULT_BUFLEN;
    // maximum buffer for messages length
    char sendbuf[DEFAULT_BUFLEN];
    char recvbuf[DEFAULT_BUFLEN];

    while (true) {
        iResult = 0;

        // Loop until the message is sent.
        bool sent = false;

        // Resetting buffers
        memset(sendbuf, 0, sizeof(sendbuf));
        memset(recvbuf, 0, sizeof(recvbuf));

        // Get user input
        fgets(sendbuf, DEFAULT_BUFLEN, stdin);
        int contentLength = strlen(sendbuf);

        char * message = sendbuf;
        sent = false;
        char * startChar;
        char * endChar;
        int startIndex = 0;
        int endIndex = DEFAULT_BUFLEN - 1;
        int netContentLength = 0;
        char * curMessage;
        u_long messageLen = strlen(message);

        while (!sent) {
            startChar = &message[startIndex];
            endChar = &message[endIndex];
            curMessage = calloc(1, endChar - startChar + 1);
            memcpy(curMessage, startChar, endChar - startChar);
            startIndex = endIndex + 1;
            endIndex = endIndex + DEFAULT_BUFLEN;

            //Current batch length.
            if (contentLength > DEFAULT_BUFLEN) {
                contentLength -= DEFAULT_BUFLEN;
                netContentLength = htonl(DEFAULT_BUFLEN);
                send(ConnectSocket, &netContentLength, 4, 0);
            }
            else if (contentLength <= DEFAULT_BUFLEN) {
                netContentLength = htonl(contentLength);
                send(ConnectSocket, &netContentLength, 4, 0);
                iResult = send(ConnectSocket, curMessage, contentLength, 0);
                sent = true;
            }


            if (iResult == SOCKET_ERROR) {
                printf("send failed: %d\n", WSAGetLastError());
                closesocket(ConnectSocket);
                WSACleanup();
                return 1;
            }
        }

        bool received = false;
        contentLength = 0;
        netContentLength = 0;

        while (!received) {
            iResult = recv(ConnectSocket, &netContentLength, 4, 0);
            contentLength = ntohl(netContentLength);
            printf("%d \n", contentLength);
            recv(ConnectSocket, message, contentLength, 0);
            printf("%s \n", message);

            if (strlen(recvbuf) < DEFAULT_BUFLEN) {
                received = true;
            }
            if (iResult > 0) {
                printf("%s \n", recvbuf);
            } else if (iResult == 0)
                printf("Connection closed\n");
            else
                printf("recv failed: %d\n", WSAGetLastError());
        }
    }
}
