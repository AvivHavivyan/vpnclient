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
        gets(sendbuf);
        int contentLength = strlen(sendbuf);
        printf("%d \n", contentLength);
        char * message = sendbuf;
        sent = false;
        char * startChar;
        char * endChar;
        int startIndex = 0;
        int endIndex = DEFAULT_BUFLEN - 1;
        u_long netContentLength = 0;
//        char * curMessage;
        netContentLength = htonl(contentLength);
        send(ConnectSocket, &netContentLength, 4, 0);
        while (!sent) {
            if (contentLength < DEFAULT_BUFLEN) {
                endIndex = contentLength;
            }
            char curMessage[endIndex - startIndex + 1];
            strncpy(curMessage, &message[startIndex], endIndex - startIndex);
//            printf(curMessage);

//            startChar = &message[startIndex];
//            endChar = &message[endIndex];
//            curMessage = calloc(1, endChar - startChar + 1);
//            memcpy(curMessage, startChar, endChar - startChar);
            startIndex = endIndex + 1;
            endIndex = endIndex + DEFAULT_BUFLEN;

            //Current batch length.
            if (contentLength > DEFAULT_BUFLEN) {
                contentLength -= DEFAULT_BUFLEN;
                iResult = send(ConnectSocket, curMessage, DEFAULT_BUFLEN, 0);
            }
            else if (contentLength <= DEFAULT_BUFLEN) {
                iResult = send(ConnectSocket, curMessage, strlen(curMessage), 0);
                sent = true;
            }

            if (iResult == SOCKET_ERROR) {
                printf("send failed: %d\n", WSAGetLastError());
                closesocket(ConnectSocket);
                WSACleanup();
                return 1;
            }
        }

        // add option to handle message len of 0.

        bool received = false;
        contentLength = 0;
        netContentLength = 0;
        netContentLength = 0;
        iResult = recv(ConnectSocket, &netContentLength, 4, 0);
        contentLength = ntohl(netContentLength);
        char fullmsg[contentLength];
        while (!received) {
            char msg[DEFAULT_BUFLEN];

            memset(msg, 0, DEFAULT_BUFLEN);
            memset(fullmsg, 0, DEFAULT_BUFLEN);
            if (contentLength < DEFAULT_BUFLEN) {
                recv(ConnectSocket, msg, contentLength, 0);
                strcat(fullmsg, msg);
                printf(fullmsg);
                received = true;
            } else {
                contentLength -= DEFAULT_BUFLEN;
                recv(ConnectSocket, msg, contentLength, 0);
                strcat(fullmsg, msg);
            }
            if (iResult == 0) {
                printf("Connection closed\n");
                WSACleanup();
                return 0;
            }
            else if (iResult < 0)
                printf("recv failed: %d\n", WSAGetLastError());
        }
    }
}
