//
// Created by Aviv on 27/01/2022.
//

#include <stdio.h>
#include <ws2tcpip.h>
#include <unistd.h>
#include <stdbool.h>
#include <openssl/crypto.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <winsock2.h>


#define DEFAULT_PORT "27015"
#define LISTEN_PORT "5102"
#define DEFAULT_BUFLEN 214
#define KEY_LEN 256
#define PEM_FILE_LEN 451
#define PRIVATE_KEY_PATH "private_client.pem"
#define PUBLIC_KEY_PATH "public_client.pem"
#define SERVER_KEY_PATH "serverkey_client.pem"
#define SESSION_ID_LEN 64

#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

//void WSAAPI freeaddrinfo( struct addrinfo* );
//
//int WSAAPI getaddrinfo( const char*, const char*, const struct addrinfo*,
//                        struct addrinfo** );
//
//int WSAAPI getnameinfo( const struct sockaddr*, socklen_t, char*, DWORD,
//                        char*, DWORD, int );


// TODO: add comments
SOCKET connectToServer(struct addrinfo * result) {
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

char * lowerString(char * str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = (char)tolower((int)str[i]);
    }
    return str;
}

int getContentLength(char * response) {
    char * header = "content-length";
    char rspcpy[strlen(response)];
    strcpy(rspcpy, response);
    lowerString(rspcpy);
    char * substr = strstr(rspcpy, header);
    char * delim = "\n";
    char * header_line = strtok(substr, delim);
    delim = ":";
    strtok(header_line, delim);

    char * len_str = strtok(NULL, delim);
    printf("lenstr: %s", len_str);

    return atoi(len_str);
}

char * retrieveKey(int flag) {

    FILE * fptr;
    int length;

    if (flag == 0) { // public key
        fptr = fopen(PUBLIC_KEY_PATH,"rb");
        if (fptr)
        {
            fseek (fptr, 0, SEEK_END);
            length = ftell (fptr);
            char buffer[length];
            char * key = malloc(PEM_FILE_LEN);
            rewind(fptr);
            if (buffer)
            {
                fread (buffer, 1, length, fptr);
                memcpy(key, buffer, PEM_FILE_LEN);
            }
            fclose (fptr);
            return key;
        }
    } else if (flag == 1) {
        // private key
        RSA * keyPair;

        FILE *fptr2;
        length = 0;

        fptr = fopen(PRIVATE_KEY_PATH,"rb");
        RSA * privateKey = RSA_new();
        EVP_PKEY * evp = EVP_PKEY_new();
        privateKey = PEM_read_RSAPrivateKey(fptr, &privateKey, NULL, NULL);
        if (privateKey == NULL) {
            return NULL;
        }
//        privateKey = EVP_PKEY_get0_RSA(evp);
        RSA_size(privateKey);
        fclose(fptr);
        return (char *)privateKey;
        
    } else { // public server key
        fptr = fopen(SERVER_KEY_PATH,"rb");
        RSA * pubkey = RSA_new();
        EVP_PKEY * evp = EVP_PKEY_new();
        evp = PEM_read_PUBKEY(fptr, &evp, NULL, NULL);
        if (evp == NULL) {
            return NULL;
        }
        pubkey = EVP_PKEY_get0_RSA(evp);
        RSA_size(pubkey);
        fclose (fptr);
        return (char *) pubkey;
    }

    return NULL;
}


int genKey() {
    // check for existing key
    FILE *fptr;
    RSA * keyPair = RSA_new();
    keyPair = malloc(KEY_LEN);
    if (retrieveKey(1) != NULL) {
        memcpy(keyPair,  (RSA *)retrieveKey(1), KEY_LEN);

        if (RSA_check_key(keyPair)) { // if there's already a key
            return 0;
        }
    }

    printf("generating key... \n");

    // generate new key using OpenSSL
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
    RSA * test = RSAPrivateKey_dup(key);


    // cache it to files.
    fptr = fopen(PRIVATE_KEY_PATH,"wb");

    PEM_write_RSAPrivateKey(fptr, test, NULL, NULL,0, 0, NULL);
    fclose(fptr);

    fptr = fopen(PUBLIC_KEY_PATH,"wb");
    PEM_write_RSA_PUBKEY(fptr,key);
    fclose(fptr);

    return 0;
}



char * keysExchange(const SOCKET *AuthSocket) {

    // request updated key if necessary
    FILE * fptr;

    char publicKeyServer[PEM_FILE_LEN];

    // receive key, make sure that all the bytes are received
    recv(*AuthSocket, publicKeyServer, PEM_FILE_LEN, MSG_WAITALL);

    printf("key: %s \n", publicKeyServer);

    // cache key
    fptr = fopen(SERVER_KEY_PATH,"wb");
    if(fptr!=NULL){
        fwrite(publicKeyServer, 1, PEM_FILE_LEN, fptr);
        fclose(fptr);
    } else {
        perror("file error");
    }

    // send client's public key
    char * publicKey = retrieveKey(0);

    send(*AuthSocket, publicKey, PEM_FILE_LEN, 0);

    // receive session ID
    u_char sessionBuff[KEY_LEN];
    u_char * sessionID = malloc(SESSION_ID_LEN);
    recv(*AuthSocket, sessionBuff, KEY_LEN, 0);

    // decrypt
    RSA * privateKeyRSA = (RSA *)retrieveKey(1);
    RSA_private_decrypt(KEY_LEN, sessionBuff, sessionID, privateKeyRSA, RSA_PKCS1_OAEP_PADDING);
    printf("session ID: %s \n", (char *) sessionID);

    fptr = fopen("session.txt","wb");
    if(fptr!=NULL){
        fwrite(sessionID, 1, SESSION_ID_LEN, fptr);
        fclose(fptr);
    } else {
        perror("file error");
    }

    return (char *) sessionID;
}


// Start a session. returns sessionID
char * auth(SOCKET * AuthSocket, int flag) {

    printf("Authenticating... \n");
    genKey();
    // check for session ID and validate time:
    char * sessionID = malloc(SESSION_ID_LEN);
    FILE *fptr;
    int length = 0;
    RSA * keyPair;

    // retrieve sessionID
    fptr = fopen("session.txt","rb");
    if (fptr)
    {
        fseek (fptr, 0, SEEK_END);
        length = ftell (fptr);
        char * buffer = malloc(length);
        memset(buffer, 0, length);
        rewind(fptr);
        if (buffer)
        {
            fread (buffer, 1, length, fptr);
            memcpy(sessionID, buffer, SESSION_ID_LEN);
        }
        fclose (fptr);
    }


    // send session ID or a null array.
    if (length == 0 || flag == 0) {
        printf("no session ID \n");
        char * emptySessionID = malloc(SESSION_ID_LEN);
        memset(emptySessionID, 0, SESSION_ID_LEN);
        send(*AuthSocket,emptySessionID, SESSION_ID_LEN, 0);
    } else {
        send(*AuthSocket,sessionID, SESSION_ID_LEN, 0);
        printf("session ID: %s", sessionID);
    }


    // receive server response...
    char * lenChar = malloc(4);
    int netContentLength = 0;
    int contentLength = 0;
    recv(*AuthSocket, &netContentLength, 4, 0);
    contentLength = ntohl(netContentLength);
    printf("contentLength: %d \n", contentLength);
    char serverResponse[contentLength];

    recv(*AuthSocket, serverResponse, contentLength, 0);


    if (strcmp("ok", serverResponse) == 0) {
        return sessionID;
    } else {
        // exchange keys again and receive new sessionID...
        printf("exchanging keys... \n");
        char * newSessionID = keysExchange(AuthSocket);

        return newSessionID;
    }
}



int client(const SOCKET * ProxySocket, struct addrinfo * result) {
    int iResult = 0;
    char sendbuf[2048];
    char proxyBuffer[DEFAULT_BUFLEN];
    RSA * keyPair;


    while (true) {
        iResult = 0;

        // Loop until the message is sent.
        bool sent = false;

        // Resetting buffers
        memset(sendbuf, 0, sizeof(sendbuf));
        memset(proxyBuffer, 0, sizeof(proxyBuffer));

        // Intercept http requests
        int bytesRecvProxy = 0;
        char * request = malloc(DEFAULT_BUFLEN);

        while (!strstr(proxyBuffer, "\r\n\r\n")) {
            memset(proxyBuffer, 0, DEFAULT_BUFLEN);

            // Peek before receiving, to see the end of the headers.
            iResult = recv(*ProxySocket, proxyBuffer, DEFAULT_BUFLEN, MSG_PEEK);
            if (strstr(proxyBuffer, "\r\n\r\n")) {
                // check the length until the CRLFCRLF sequence
                char * bufferPointer = proxyBuffer;
                char * end = strstr(proxyBuffer, "\r\n\r\n");
                int lastChunkLen = end - bufferPointer + 4;
                memset(proxyBuffer, 0, DEFAULT_BUFLEN);
                iResult = recv(*ProxySocket, proxyBuffer, lastChunkLen, 0);
            } else {
                iResult = recv(*ProxySocket, proxyBuffer, DEFAULT_BUFLEN, 0);
            }
            if (iResult == SOCKET_ERROR) {
                closesocket(*ProxySocket);
                return -1;
            }

            request = (char *) realloc(request, bytesRecvProxy + iResult);
            memset(request + bytesRecvProxy, 0, iResult);

            memcpy(request + bytesRecvProxy, proxyBuffer, iResult);

            bytesRecvProxy += iResult;
            if (iResult == SOCKET_ERROR)
                return -1;
        }

        //filter out https requests (e.g. CONNECT)

        // TODO: (improve filtering - to be within the first word.)
        if (strstr(request, "CONNECT")) {
            break;
        }

        int contentLength = 0;
        char requestCopyTmp[strlen(request)];
        strcpy(requestCopyTmp, request);
        int total = bytesRecvProxy;

        if (strstr(lowerString(requestCopyTmp), "content-length")) {
            char * terminators = strstr(request, "\r\n\r\n");
            int headers_len = (int)(terminators - request);
            int len = getContentLength(request);

            total = headers_len + len + 4;
            recv(*ProxySocket, proxyBuffer, len, MSG_WAITALL);
            request = (char *) realloc(request,  total);
            memcpy(request, proxyBuffer, headers_len + 4);
        }

        printf(request);
        contentLength = total;

        SOCKET VpnSocket = connectToServer(result);

        // if no server key
        if (retrieveKey(2) == NULL) {
            auth(&VpnSocket, 0);

        } else {
            auth(&VpnSocket, 1);
        }
        printf("authentication complete. \n");
        keyPair = (RSA *)retrieveKey(1);


        char * message = request;
        sent = false;
        int bytesLeft = contentLength;
        int startIndex = 0;
        int endIndex = DEFAULT_BUFLEN;
        u_char bytesInt[4];
        RSA * serverKey = (RSA *)retrieveKey(2);
        u_char encryptedBytes[RSA_size(serverKey)];

        printf("Content Length: %d", contentLength);

        memcpy(bytesInt, &contentLength, 4);
        RSA_public_encrypt(4, bytesInt, encryptedBytes, serverKey, RSA_PKCS1_OAEP_PADDING);

        // send the length of the request to the server as part of the protocol
        send(VpnSocket, encryptedBytes, KEY_LEN,0);

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
            if (bytesLeft > DEFAULT_BUFLEN) {
                u_char messageBytes[DEFAULT_BUFLEN];
                u_char encryptedMessage[RSA_size(serverKey)];
                memset(encryptedMessage, 0, RSA_size(serverKey));
                memcpy(messageBytes, curMessage, DEFAULT_BUFLEN);

                RSA_public_encrypt(DEFAULT_BUFLEN, messageBytes, encryptedMessage, serverKey, RSA_PKCS1_OAEP_PADDING);

                iResult = send(VpnSocket, encryptedMessage, KEY_LEN, 0);
                startIndex = endIndex;
                endIndex = endIndex + DEFAULT_BUFLEN;
            }

            // Final batch.
            else if (bytesLeft <= DEFAULT_BUFLEN) {
                u_char messageBytes[bytesLeft];
                u_char encryptedMessage[RSA_size(serverKey)];
                memcpy(messageBytes, curMessage, bytesLeft);

                RSA_public_encrypt(bytesLeft, messageBytes, encryptedMessage, serverKey, RSA_PKCS1_OAEP_PADDING);

                iResult = send(VpnSocket, encryptedMessage, KEY_LEN, 0);
                bytesLeft = 0;
                sent = true;
            }

            bytesLeft -= DEFAULT_BUFLEN;

            if (iResult == SOCKET_ERROR) {
                printf("send failed: %d\n", WSAGetLastError());
                closesocket(VpnSocket);
                WSACleanup();
                return 1;
            }
        }
        int bytesRecv = 0;

        // RECEIVING PART //

        // Receive response length
        iResult = 0;
        u_char bytes[KEY_LEN];
        u_char buffer[KEY_LEN];
        u_char decryptedBytes[4];
        memset(bytes, 0, KEY_LEN);
        bytesRecv = 0;


        while (bytesRecv < KEY_LEN) {
            iResult = recv(VpnSocket, buffer, KEY_LEN, 0);
            memcpy(bytes + bytesRecv, buffer, iResult);
            bytesRecv += iResult;

        }

        RSA_private_decrypt(KEY_LEN, bytes, decryptedBytes, keyPair, RSA_PKCS1_OAEP_PADDING);
        memcpy(&contentLength, decryptedBytes, 4);

        bytesLeft = contentLength;

        // Message to be sent, buffer is appended to it.
        char fullmsg[contentLength];
        memset(fullmsg, 0, strlen(fullmsg));

        if (contentLength == 0) {
            printf("Connection to vpn server terminated unexpectedly.");
            closesocket(VpnSocket);
            WSACleanup();
            return -1;
        }

        u_char encryptedMessage[KEY_LEN];
        bytesRecv = 0;

        // Receive the response content
        while (1) {
            char recvbuf[KEY_LEN];

            memset(recvbuf, 0, DEFAULT_BUFLEN);

            // Final batch reached
            if (bytesLeft < DEFAULT_BUFLEN) {
                u_char decryptedMessage[bytesLeft];
                int bytesRecvBuf = 0;
                while (bytesRecvBuf < KEY_LEN) {
                    iResult = recv(VpnSocket, buffer, KEY_LEN, 0);
                    memcpy(recvbuf + bytesRecvBuf, buffer, iResult);
                    bytesRecvBuf += iResult;
                }

                memcpy(encryptedMessage, recvbuf, KEY_LEN);

                RSA_private_decrypt(KEY_LEN, encryptedMessage, decryptedMessage, keyPair, RSA_PKCS1_OAEP_PADDING);

                memcpy(fullmsg + bytesRecv, decryptedMessage, bytesLeft);

                bytesLeft -= iResult;

                // Logging
                printf("fullmsg: %s \n", fullmsg);
                printf("total: %d \n", contentLength);

                // Send to win proxy (which in turn will send to browser) and exit the function,
                // closing open sockets.
                send(*ProxySocket, fullmsg, contentLength, 0);
                closesocket(*ProxySocket);
                closesocket(VpnSocket);
                return 0;
            } else {
                u_char decryptedMessage[DEFAULT_BUFLEN];

                int bytesRecvBuf = 0;
                while (bytesRecvBuf < KEY_LEN) {
                    iResult = recv(VpnSocket, buffer, KEY_LEN, 0);
                    memcpy(recvbuf + bytesRecvBuf, buffer, iResult);
                    bytesRecvBuf += iResult;
                }
                // Any other batch - receive and append.
                memcpy(encryptedMessage, recvbuf, KEY_LEN);

                RSA_private_decrypt(KEY_LEN,encryptedMessage, decryptedMessage, keyPair, RSA_PKCS1_OAEP_PADDING);

                memcpy(fullmsg + bytesRecv, decryptedMessage, DEFAULT_BUFLEN);

                bytesLeft -= DEFAULT_BUFLEN;
            }

            bytesRecv += DEFAULT_BUFLEN;

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

// TODO: add multithreading?


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
    OPENSSL_INIT_new();

    RSA * key = RSA_new();


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
        if (iResult != 0) {
            printf("getaddrinfo failed: %d, couldn't connect to server\n", iResult);
            WSACleanup();
            return 1;
        }

        client(&ProxySocket, result);
    }
#pragma clang diagnostic pop
}
