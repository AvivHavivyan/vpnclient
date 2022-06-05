//
// Created by Aviv on 27/01/2022.
//

#include <stdio.h>
#include <ws2tcpip.h>
#include <unistd.h>
#include <stdbool.h>
#include <process.h>
#include <time.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>

#define DEFAULT_PORT "27015"
#define LISTEN_PORT "5102"
#define DEFAULT_BUFLEN 512
#define KEY_LEN 256

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

// Start a session
int auth(struct addrinfo * server, RSA * key) {
    // connect
    SOCKET AuthSocket = connecttoserver(server);

    // check server's public key
//    time_t t = time();

    // request updated key if necessary
    char * requestMsg = "get-key";
    int contentLength = strlen(requestMsg);
    u_long netContentLength = 0;
    netContentLength = htonl(contentLength);
    send(AuthSocket, &netContentLength, 4, 0);

    send(AuthSocket, requestMsg, contentLength, 0);
    char publicKeyServer[KEY_LEN];

    // receive key
    recv(AuthSocket, publicKeyServer, KEY_LEN, 0);

    // cache key
    FILE *fptr;
    fptr = fopen("C:\\Users\\Aviv\\serverkey_client.pem","wb");
    if(fptr!=NULL){
        fwrite(publicKeyServer, 1, KEY_LEN, fptr);
        fclose(fptr);
    } else {
        perror("file error");
    }
    int length;

    // send client's public key
    fptr = fopen("C:\\Users\\Aviv\\public_client.pem","rb");
    if (fptr)
    {
        fseek (fptr, 0, SEEK_END);
        length = ftell (fptr);
        char buffer[length];
        rewind(fptr);
        if (buffer)
        {
            fread (buffer, 1, length, fptr);
        }
        fclose (fptr);
        send(AuthSocket, buffer, 256, 0);
        closesocket(AuthSocket);
        return 0;
    }

    return 0;
}

int genKey() {
    // check for existing key
    RSA * key = 0;
    struct bignum_st * bn = 0;
    int err = 0;
    if (!(key = RSA_new())) return -1;
    if (!(bn = BN_new())) return -2;
    if (!(err = BN_set_word(bn,RSA_F4))) {
        BN_free(bn);
        return err;
    }

    if (!(err = RSA_generate_key_ex(key,2048,bn,NULL))) {
        BN_free(bn);
        RSA_free(key);
        return err;
    }

    RSA * private = RSAPrivateKey_dup(key);
    RSA * public = RSAPublicKey_dup(key);

    const unsigned char test[4] = "Test";
    u_char encrypted[RSA_size(key)];
    RSA_public_encrypt(4, test, encrypted, key, RSA_PKCS1_OAEP_PADDING);
    u_char decrypted[4];
    RSA_private_decrypt(256, encrypted, decrypted, key, RSA_PKCS1_OAEP_PADDING);


    FILE *fptr;
    fptr = fopen("C:\\Users\\Aviv\\private_client.pem","wb");
    fwrite(key, 1, 256, fptr);
    fclose(fptr);

    fptr = fopen("C:\\Users\\Aviv\\public_client.pem","wb");
    fwrite(public, 1, 256, fptr);
    fclose(fptr);

    return 0;
}

int thread(SOCKET * ProxySocket, struct addrinfo * listen_addr, struct addrinfo * ptr, struct addrinfo * result) {
    int iResult = 0;
    char sendbuf[2048];
    char recvbuf[DEFAULT_BUFLEN];
    RSA * keypair;
    RSA * serverKey;
    FILE *fptr;
    int length = 0;

    fptr = fopen("C:\\Users\\Aviv\\private_client.pem","rb");
    if (fptr)
    {
        fseek (fptr, 0, SEEK_END);
        length = ftell (fptr);
        char buffer[length];
        rewind(fptr);
        if (buffer)
        {
            fread (buffer, 1, length, fptr);
            keypair = (RSA *)buffer;
        }
        fclose (fptr);
    }

    fptr = fopen("C:\\Users\\Aviv\\serverkey_client.pem","rb");
    if (fptr)
    {
        fseek (fptr, 0, SEEK_END);
        length = ftell (fptr);
        char buffer[length];
        rewind(fptr);
        fread (buffer, 1, length, fptr);
        serverKey = (RSA *)buffer;
        fclose (fptr);
    } else {
        printf("No key was found. restart the client to try again");
        return -1;
    }


    while (true) {
        iResult = 0;

        // Loop until the message is sent.
        bool sent = false;

        // Resetting buffers
        memset(sendbuf, 0, sizeof(sendbuf));
        memset(recvbuf, 0, sizeof(recvbuf));

        // Intercept http requests
        // TODO: get entire requests.
        iResult = recv(*ProxySocket, sendbuf, 2048, 0);


        //filter out https requests (e.g. CONNECT)
        // TODO: (improve filtering - to be within the first word.)
        if (strstr(sendbuf, "CONNECT")) {
            break;
        }


        // cut out accept encoding
        // TODO: test that it's only GET
        char * pointer = strstr(sendbuf,"Accept-Encoding");
        memset(pointer, 0, strlen(pointer));
        strcat(sendbuf, "\r\n\r\n");

        printf(sendbuf);

        SOCKET VpnSocket = connecttoserver(result);

        int contentLength = iResult;
        char * message = sendbuf;
        sent = false;
        int bytes_left = contentLength;
        int startIndex = 0;
        int endIndex = DEFAULT_BUFLEN;
        u_long netContentLength = 0;

        // send the length of the request to the server as part of the protocol
        netContentLength = htonl(contentLength);
        unsigned char * netLen = (unsigned char * )&netContentLength;

        send(VpnSocket, &netContentLength, 4, 0);

        // main loop, send the request to the server.
        while (!sent) {

            // if the final batch is reached, endIndex would be the content length.
            if (contentLength < DEFAULT_BUFLEN) {
                endIndex = contentLength;
            }

            // Reset variables to use, set curMessage to the updated endIndex
            char curMessage[endIndex];
            memset(curMessage, 0, DEFAULT_BUFLEN);
            memcpy(curMessage, &message[startIndex], endIndex - startIndex);

            //Current batch length.
            if (bytes_left > DEFAULT_BUFLEN) {
                iResult = send(VpnSocket, curMessage, DEFAULT_BUFLEN, 0);
                startIndex = endIndex;
                endIndex = endIndex + DEFAULT_BUFLEN;
            }

            // Final batch.
            else if (bytes_left <= DEFAULT_BUFLEN) {
                iResult = send(VpnSocket, curMessage, bytes_left, 0);
                bytes_left = 0;
                sent = true;
            }

            bytes_left -= iResult;

            if (iResult == SOCKET_ERROR) {
                printf("send failed: %d\n", WSAGetLastError());
                closesocket(VpnSocket);
                WSACleanup();
                return 1;
            }
        }

        // TODO: add option to handle message len of 0.

        // RECEIVING PART //

        // Receive response length
        netContentLength = 0;
        iResult = 0;

        while (iResult == 0) {
            iResult = recv(VpnSocket, &netContentLength, 4, 0);
        }

        contentLength = ntohl(netContentLength);
        bytes_left = contentLength;

        // Message to be sent, buffer is appended to it.
        char fullmsg[contentLength];
        memset(fullmsg, 0, strlen(fullmsg));

        if (contentLength == 0) {
            printf("Connection to vpn server terminated unexpectedly.");
            closesocket(VpnSocket);
            WSACleanup();
            return -1;
        }

        int prevLen = 0;

        // Receive the response content
        while (1) {
            char msg[DEFAULT_BUFLEN];

            memset(msg, 0, DEFAULT_BUFLEN);

            // Final batch reached
            if (bytes_left < DEFAULT_BUFLEN) {
                iResult = recv(VpnSocket, msg, bytes_left, 0);
                memset(fullmsg + prevLen, 0, iResult);
                memcpy(fullmsg + prevLen, msg, iResult);
                bytes_left -= iResult;

//                FILE *fptr;
//                fptr = fopen("C:\\Users\\Aviv\\client.bin","wb");
//                fwrite(fullmsg, 1, contentLength, fptr);
//                fclose(fptr);

                // Logging
                printf("fullmsg: %s", fullmsg);
                printf("total: %d", contentLength);

                // Send to win proxy (which in turn will send to browser) and exit the function,
                // closing open sockets.
                send(*ProxySocket, fullmsg, contentLength, 0);
                closesocket(*ProxySocket);
                closesocket(VpnSocket);
                return 0;
            } else {
                // Any other batch - receive and append.
                iResult = recv(VpnSocket, msg, DEFAULT_BUFLEN, 0);
                memcpy(fullmsg + prevLen, msg, iResult);

                prevLen += iResult;
                bytes_left -= iResult;
            }

            if (iResult == SOCKET_ERROR) {
                printf("Connection closed\n");
                WSACleanup();
                return 1;
            }
            else if (iResult < 0)
                printf("recv failed: %d\n", WSAGetLastError());
        }

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

    RSA * key = RSA_new();
    genKey();
    auth(result, key);

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

        iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &result);

        thread( &ProxySocket, listen_addr, ptr, result);
    }
#pragma clang diagnostic pop
}
