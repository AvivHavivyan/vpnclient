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


#define DEFAULT_PORT "27015" // server port
#define LISTEN_PORT "5102" // windows proxy port
#define DEFAULT_BUFLEN 214 // maximum chunk length
#define KEY_LEN 256 // RSA key length
#define PEM_FILE_LEN 451
#define PRIVATE_KEY_PATH "private_client.pem" // key files
#define PUBLIC_KEY_PATH "public_client.pem"
#define SERVER_KEY_PATH "serverkey_client.pem"
#define SESSION_ID_LEN 64 // session ID length in HEX format

// link libraries.
#pragma comment (lib, "Ws2_32.lib")
#pragma comment (lib, "Mswsock.lib")
#pragma comment (lib, "AdvApi32.lib")

SOCKET connectToServer(struct addrinfo *result) {
    int iResult;

// Create a SOCKET for connecting to server, using the addrinfo struct for the server's address
    SOCKET ConnectSocket = socket(result->ai_family, result->ai_socktype, result->ai_protocol);

    if (ConnectSocket == INVALID_SOCKET) {
        printf("Error at socket(): %ld\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    // Connect to server.
    iResult = connect(ConnectSocket, result->ai_addr, (int) result->ai_addrlen);
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

// a function that takes a string and converts it to lowercase letters.
char *lowerString(char *str) {
    for (int i = 0; i < strlen(str); i++) {
        str[i] = (char) tolower((int) str[i]);
    }
    return str;
}

// a function that retrieves the content length from an HTTP headers section
int getContentLength(char *response) {
    char *header = "content-length";
    char rspcpy[strlen(response)];
    strcpy(rspcpy, response);
    lowerString(rspcpy);
    char *substr = strstr(rspcpy, header);
    char *delim = "\n";
    char *header_line = strtok(substr, delim);
    delim = ":";
    strtok(header_line, delim);

    char *len_str = strtok(NULL, delim);
    printf("lenstr: %s", len_str);

    return strtol(len_str, NULL, 10);

}


// a function that retrieves the requested key - according to 3 flags:
// 0 - public client key
// 1 - private client key
// 2 - public server key
char *retrieveKey(int flag) {

    FILE *fptr;
    int length;

    if (flag == 0) { // public key
        fptr = fopen(PUBLIC_KEY_PATH, "rb");
        if (fptr) {
            fseek(fptr, 0, SEEK_END);
            length = ftell(fptr);
            char buffer[length];
            char *key = malloc(PEM_FILE_LEN);
            rewind(fptr);
            fread(buffer, 1, length, fptr);
            memcpy(key, buffer, PEM_FILE_LEN);
            fclose(fptr);
            return key;
        }
    } else if (flag == 1) {
        // private key

        fptr = fopen(PRIVATE_KEY_PATH, "rb");
        RSA *privateKey = RSA_new();
        privateKey = PEM_read_RSAPrivateKey(fptr, &privateKey, NULL, NULL);
        if (privateKey == NULL) {
            return NULL;
        }
        RSA_size(privateKey);
        fclose(fptr);
        return (char *) privateKey;

    } else { // public server key
        fptr = fopen(SERVER_KEY_PATH, "rb");
        RSA *pubkey;
        EVP_PKEY *evp = EVP_PKEY_new();
        evp = PEM_read_PUBKEY(fptr, &evp, NULL, NULL);
        if (evp == NULL) {
            return NULL;
        }
        pubkey = EVP_PKEY_get0_RSA(evp);
        RSA_size(pubkey);
        fclose(fptr);
        return (char *) pubkey;
    }

    return NULL;
}


// a function that generates keys if it does not find existing ones
// in the program files in the specified path.
int genKey() {
    FILE *fptr;
    RSA *keyPair;
    keyPair = malloc(KEY_LEN);

    // check for existing key in cached files
    if (retrieveKey(1) != NULL) {
        memcpy(keyPair, (RSA *) retrieveKey(1), KEY_LEN);

        if (RSA_check_key(keyPair)) { // if there's already a key
            return 0;
        }
    }

    // generate new key if one was not found
    printf("generating key... \n");

    // generate new key using OpenSSL
    RSA *key;
    struct bignum_st *bn;
    int err;
    if (!(key = RSA_new())) return -1;
    if (!(bn = BN_new())) return -2;
    if (!(err = BN_set_word(bn, RSA_F4))) {
        BN_free(bn);
        return err;
    }

    if (!(err = RSA_generate_key_ex(key, 2048, bn, NULL))) {
        BN_free(bn);
        RSA_free(key);
        return err;
    }

    RSA * privateKey = RSAPrivateKey_dup(key);


    // cache the private and public key to two files using the PEM library
    fptr = fopen(PRIVATE_KEY_PATH, "wb");

    PEM_write_RSAPrivateKey(fptr, privateKey, NULL, NULL, 0, 0, NULL);
    fclose(fptr);

    fptr = fopen(PUBLIC_KEY_PATH, "wb");
    PEM_write_RSA_PUBKEY(fptr, key);
    fclose(fptr);

    return 0;
}


// a function that facilitates the keys exchange between the server and the client,
// and returned the newly assigned session ID received from the server.
char *keysExchange(const SOCKET *AuthSocket) {

    // request updated key if necessary
    FILE *fptr;

    char publicKeyServer[PEM_FILE_LEN];

    // receive key, make sure that all the bytes are received
    recv(*AuthSocket, publicKeyServer, PEM_FILE_LEN, MSG_WAITALL);

    printf("key: %s \n", publicKeyServer);

    // cache key
    fptr = fopen(SERVER_KEY_PATH, "wb");
    if (fptr != NULL) {
        fwrite(publicKeyServer, 1, PEM_FILE_LEN, fptr);
        fclose(fptr);
    } else {
        perror("file error");
    }

    // send client's public key
    char *publicKey = retrieveKey(0);

    send(*AuthSocket, publicKey, PEM_FILE_LEN, 0);

    // receive session ID
    u_char sessionBuff[KEY_LEN];
    u_char *sessionID = malloc(SESSION_ID_LEN);
    recv(*AuthSocket, (char *)sessionBuff, KEY_LEN, 0);

    // decrypt
    RSA *privateKeyRSA = (RSA *) retrieveKey(1);
    RSA_private_decrypt(KEY_LEN, sessionBuff, sessionID, privateKeyRSA, RSA_PKCS1_OAEP_PADDING);
    printf("session ID: %s \n", (char *) sessionID);

    // cache the session ID
    fptr = fopen("session.txt", "wb");
    if (fptr != NULL) {
        fwrite(sessionID, 1, SESSION_ID_LEN, fptr);
        fclose(fptr);
    } else {
        perror("file error");
    }

    return (char *) sessionID;
}


// Start a session. returns sessionID
char *auth(SOCKET *AuthSocket, int flag) {

    printf("Authenticating... \n");
    // call the function to generate keys if necessary.
    genKey();

    // check for session ID in cached files
    char *sessionID = malloc(SESSION_ID_LEN);
    FILE *fptr;
    int length = 0;

    // retrieve sessionID
    fptr = fopen("session.txt", "rb");
    if (fptr) {
        fseek(fptr, 0, SEEK_END);
        length = ftell(fptr);
        char *buffer = malloc(length);
        memset(buffer, 0, length);
        rewind(fptr);
        if (buffer) {
            fread(buffer, 1, length, fptr);
            memcpy(sessionID, buffer, SESSION_ID_LEN);
        }
        fclose(fptr);
    }


    // send session ID, or a null array to server if a session ID or a server key is not found.
    if (length == 0 || flag == 0) {
        printf("no session ID \n");
        char *emptySessionID = malloc(SESSION_ID_LEN);
        memset(emptySessionID, 0, SESSION_ID_LEN);
        send(*AuthSocket, emptySessionID, SESSION_ID_LEN, 0);
    } else {
        send(*AuthSocket, sessionID, SESSION_ID_LEN, 0);
        printf("session ID: %s", sessionID);
    }

    // receive server response...
    int netContentLength = 0;
    int contentLength;

    // receive length
    recv(*AuthSocket, (char *)&netContentLength, 4, 0);
    contentLength = (int)ntohl(netContentLength);
    printf("contentLength: %d \n", contentLength);

    char serverResponse[contentLength];

    // receive response content
    recv(*AuthSocket, serverResponse, contentLength, 0);

    // if the server responds with "ok", the authentication was successful
    // and the session ID is valid. else, the key exchange process is
    // initiated and a new session ID is generated.
    if (strcmp("ok", serverResponse) == 0) {
        return sessionID;
    } else {
        // exchange keys again and receive new sessionID...
        printf("exchanging keys... \n");
        char *newSessionID = keysExchange(AuthSocket);

        return newSessionID;
    }
}


// Main client function, utilizes different functions and controls the flow of the
// client program. executes authentication, intercepts HTTP requests from host pc,
// forwards them to the server and receives a response, forwarding it to windows proxy.
int client(const SOCKET *ProxySocket, struct addrinfo *result) {
    int iResult;
    char sendbuf[2048];
    char proxyBuffer[DEFAULT_BUFLEN];
    RSA *privateKey;

    while (true) {
        iResult = 0;

        // Loop until the message is sent.
        bool sent = false;

        // Resetting buffers
        memset(sendbuf, 0, sizeof(sendbuf));
        memset(proxyBuffer, 0, sizeof(proxyBuffer));

        // Intercept http requests
        int bytesRecvProxy = 0;
        // allocate initial size
        char *request = malloc(DEFAULT_BUFLEN);

        while (!strstr(proxyBuffer, "\r\n\r\n")) {
            memset(proxyBuffer, 0, DEFAULT_BUFLEN);

            // Peek before receiving, to see the end of the headers,
            // and what the length of the last headers chunk is.
            iResult = recv(*ProxySocket, proxyBuffer, DEFAULT_BUFLEN, MSG_PEEK);
            if (iResult == SOCKET_ERROR) {
                closesocket(*ProxySocket);
                return -1;
            }
            if (strstr(proxyBuffer, "\r\n\r\n")) {
                // check the length until the CRLFCRLF sequence
                char *bufferPointer = proxyBuffer;
                // get pointer to the end of the headers - which starts at CRLFCRLF
                char *end = strstr(proxyBuffer, "\r\n\r\n");
                // get the length of the chunk using pointer arithmetics
                int lastChunkLen = (int)(end - bufferPointer) + 4;
                memset(proxyBuffer, 0, DEFAULT_BUFLEN);
                iResult = recv(*ProxySocket, proxyBuffer, lastChunkLen, 0);
            } else {
                iResult = recv(*ProxySocket, proxyBuffer, DEFAULT_BUFLEN, 0);
            }
            // if an error occurs
            if (iResult == SOCKET_ERROR) {
                closesocket(*ProxySocket);
                return -1;
            }

            // reallocate memory for the new bytes, reset it and copy the buffer to the newly allocated memory.
            request = (char *) realloc(request, bytesRecvProxy + iResult);
            memset(request + bytesRecvProxy, 0, iResult);
            memcpy(request + bytesRecvProxy, proxyBuffer, iResult);

            bytesRecvProxy += iResult;
        }

        //filter out https requests (e.g. CONNECT)

        // TODO: (improve filtering - to be within the first word.)
        if (strstr(request, "CONNECT")) {
            break;
        }


        int contentLength = 0;

        // temporary copy, to hold the lowercased request
        char requestCopyTmp[strlen(request)];
        strcpy(requestCopyTmp, request);
        int total = bytesRecvProxy; // total length of the request (up until this point it's only the headers part)

        // make a lowercase string for ease of comparison, then look for the "content-length"
        // header to determine whether or not further receiving from win proxy is necessary
        if (strstr(lowerString(requestCopyTmp), "content-length")) {

            // get the pointer to the start of the crlfcrlf sequence at the end of the headers
            char *crlfcrlf = strstr(request, "\r\n\r\n");

            // get the length of the headers, which can be found using the address of the CRLFCRL
            // minus the address of the beginning of the request.
            int headers_len = (int) (crlfcrlf - request);

            // get content length from the headers
            int bodyLen = getContentLength(request);

            // total is the length of the entire request - headers + crlfcrlf sequence + body
            total = headers_len + bodyLen + 4;

            // receive the entirety of the body from win proxy
            recv(*ProxySocket, proxyBuffer, bodyLen, MSG_WAITALL);

            // append to request
            request = (char *) realloc(request, total);
            memcpy(request, proxyBuffer, headers_len + 4);
        }

        // logging
        printf("%s \n",request);
        contentLength = total;

        // call a function to connect to the vpn server
        SOCKET VpnSocket = connectToServer(result);

        // if no server key is found, call auth with the 0 flag to indicate that a new session ID/key is needed.
        if (retrieveKey(2) == NULL) {
            auth(&VpnSocket, 0);
        } else { // call auth with 1 - a key server key is found.
            auth(&VpnSocket, 1);
        }

        // logging
        printf("authentication complete. \n");

        // retrieve client private key
        privateKey = (RSA *) retrieveKey(1);

        // pointer to request in order to be able to read in chunks
        // and copy to the current message char array.
        char *message = request;
        sent = false; // conditional to indicate whether a request was fully sent or not.
        int bytesLeft = contentLength;

        // integers that indicate the start and end index of the current chunk
        int startIndex = 0;
        int endIndex = DEFAULT_BUFLEN;

        // send content length of the message to the server
        u_char contentLengthBytes[4];

        // get the server's public key
        RSA *serverKey = (RSA *) retrieveKey(2);
        u_char encryptedContentLength[RSA_size(serverKey)];

        // logging
        printf("Content Length: %d", contentLength);

        // copy the contentLength pointer to contentLength bytes, for the server to read later.
        memcpy(contentLengthBytes, &contentLength, 4);

        RSA_public_encrypt(4, contentLengthBytes, encryptedContentLength, serverKey, RSA_PKCS1_OAEP_PADDING);

        // send the length of the request to the server as part of the protocol
        send(VpnSocket, (char *)encryptedContentLength, KEY_LEN, 0);

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

            // if the number of bytes left is greater than the default buffer length, encrypt
            // the maximum number of bytes allowed (which is DEFAULT_BUFLEN) and send'
            // (encrypted it would be the length of the RSA key).
            if (bytesLeft > DEFAULT_BUFLEN) {

                u_char messageBytes[DEFAULT_BUFLEN];
                u_char encryptedMessage[RSA_size(serverKey)];
                memset(encryptedMessage, 0, RSA_size(serverKey));
                memcpy(messageBytes, curMessage, DEFAULT_BUFLEN);

                RSA_public_encrypt(DEFAULT_BUFLEN, messageBytes, encryptedMessage, serverKey, RSA_PKCS1_OAEP_PADDING);

                iResult = send(VpnSocket, (char *) encryptedMessage, KEY_LEN, 0);
                startIndex = endIndex;
                endIndex = endIndex + DEFAULT_BUFLEN; // update endIndex
            }

            // Final batch. encrypt and send to server
            else if (bytesLeft <= DEFAULT_BUFLEN) {
                u_char messageBytes[bytesLeft];
                u_char encryptedMessage[RSA_size(serverKey)];
                memcpy(messageBytes, curMessage, bytesLeft);

                RSA_public_encrypt(bytesLeft, messageBytes, encryptedMessage, serverKey, RSA_PKCS1_OAEP_PADDING);

                iResult = send(VpnSocket, (char *) encryptedMessage, KEY_LEN, 0);
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

        int bytesRecv;

        // RECEIVING PART //

        // Receive response length
        u_char contentLenBytes[KEY_LEN];
        u_char decryptedLen[4]; // the length is the size of the integer type.
        memset(contentLenBytes, 0, KEY_LEN);

        // receive the length of the oncoming message as encrypted bytes
        iResult = recv(VpnSocket, (char *)contentLenBytes, KEY_LEN, MSG_WAITALL);

        // if the server sent an invalid response.
        if (iResult != KEY_LEN) {
            printf("A server error occured... \n");
            return -1;
        } else if (iResult < 0)
            printf("recv failed: %d\n", WSAGetLastError());


        RSA_private_decrypt(KEY_LEN, contentLenBytes, decryptedLen, privateKey, RSA_PKCS1_OAEP_PADDING);

        memcpy(&contentLength, decryptedLen, 4);

        bytesLeft = contentLength;

        // Message to be sent, buffer is appended to it.
        char fullResponse[contentLength];
        memset(fullResponse, 0, strlen(fullResponse));

        // if no message is received
        if (contentLength == 0) {
            printf("Connection to vpn server terminated unexpectedly.");
            closesocket(VpnSocket);
            WSACleanup();
            return -1;
        }

        // unsigned char array to hold the encrypted message,
        // with the length that's the number of contentLenBytes left - each encrypted message
        // is the length of the encryption key (in contentLenBytes)
        u_char encryptedMessage[KEY_LEN];
        bytesRecv = 0;

        // Receive the server response content
        while (1) {
            // buffer for the recv function the length of the key,
            char recvbuf[KEY_LEN];

            memset(recvbuf, 0, DEFAULT_BUFLEN);

            // Final batch reached - receive, encrypt and send to windows proxy,
            // then close the sockets and exit the function.
            if (bytesLeft < DEFAULT_BUFLEN) {
                // the length of the last decrypted message is contentLength minus the number of contentLenBytes received,
                // since we count the contentLenBytes received in their decrypted form.
                u_char decryptedMessage[bytesLeft];

                iResult = recv(VpnSocket, recvbuf, KEY_LEN, MSG_WAITALL);

                if (iResult != KEY_LEN) {
                    printf("A server error occured... \n");
                    return -1;
                } else if (iResult < 0)
                    printf("recv failed: %d\n", WSAGetLastError());

                memcpy(encryptedMessage, recvbuf, KEY_LEN);

                // decrypt chunk using the client's private key and with the specified padding
                RSA_private_decrypt(KEY_LEN, encryptedMessage, decryptedMessage, privateKey, RSA_PKCS1_OAEP_PADDING);

                // copy the last decrypted message chunk to the full message.
                memcpy(fullResponse + bytesRecv, decryptedMessage, bytesLeft);

                // Logging
                printf("fullResponse: %s \n", fullResponse);
                printf("total: %d \n", contentLength);

                // Send to win proxy (which in turn will send to browser) and exit the function,
                // closing open sockets.
                send(*ProxySocket, fullResponse, contentLength, 0);
                closesocket(*ProxySocket);
                closesocket(VpnSocket);
                return 0;
            } else {
                // any other batch, receive, encrypt and append to the full response
                u_char decryptedMessage[DEFAULT_BUFLEN];

                iResult = recv(VpnSocket, recvbuf, KEY_LEN, MSG_WAITALL);

                if (iResult != KEY_LEN) {
                    printf("A server error occured... \n");
                    return -1;
                } else if (iResult < 0)
                    printf("recv failed: %d\n", WSAGetLastError());

                memcpy(encryptedMessage, recvbuf, KEY_LEN);

                RSA_private_decrypt(KEY_LEN, encryptedMessage, decryptedMessage, privateKey, RSA_PKCS1_OAEP_PADDING);

                memcpy(fullResponse + bytesRecv, decryptedMessage, DEFAULT_BUFLEN);

                // reduce the number of contentLenBytes left to receive - we count the contentLenBytes
                // received and left in their decrypted form rather than the actual
                // number of contentLenBytes received for ease of readability
                bytesLeft -= DEFAULT_BUFLEN;
            }

            // add default buffer length to the number of contentLenBytes received to keep track of the length.
            bytesRecv += DEFAULT_BUFLEN;
        }

    }

}


int main() {
    WSADATA wsaData;
    int iResult; // hold the exit code of various functions for error catching

// Initialize Winsock
    iResult = WSAStartup(MAKEWORD(2, 2), &wsaData);
    if (iResult != 0) {
        printf("WSAStartup failed: %d\n", iResult);
        return 1;
    }

    // structs that hold address information
    struct addrinfo *serv = NULL,
            *listenAddres = NULL,
            hints;

    // reset the memory of hints and set values for each of the following parameters: internet protocol v4, tcp etc
    ZeroMemory(&hints, sizeof(hints));

    // hints - to match the desire connection type.
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_STREAM;
    hints.ai_protocol = IPPROTO_TCP;


    // resolve address information for listen socket
    iResult = getaddrinfo("127.0.0.1", LISTEN_PORT, &hints, &listenAddres);
    if (iResult != 0) {
        printf("getaddrinfo failed: %d\n", iResult);
        WSACleanup();
        return 1;
    }

    SOCKET ListenSocket = INVALID_SOCKET;

    // create the socket
    ListenSocket = socket(listenAddres->ai_family, listenAddres->ai_socktype, listenAddres->ai_protocol);

    system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v \"ProxyServer\" /t REG_SZ /d \"127.0.0.1:5102\" /f");
    system("reg add \"HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Internet Settings\" /v \"ProxyEnable\" /t REG_DWORD /d \"1\" /f");

    // bind to the address and port
    iResult = bind(ListenSocket, listenAddres->ai_addr, (int) listenAddres->ai_addrlen);
    if (iResult == SOCKET_ERROR) {
        return 1;
    }

    // initialize openssl
    OPENSSL_INIT_new();

#pragma clang diagnostic push
#pragma ide diagnostic ignored "EndlessLoop"
    while (1) {

        // create a listen socket to accept windows proxy requests.
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

        // Resolve the server address and port into an addrinfo struct
        iResult = getaddrinfo("127.0.0.1", DEFAULT_PORT, &hints, &serv);
        if (iResult != 0) {
            printf("getaddrinfo failed: %d, couldn't connect to server\n", iResult);
            WSACleanup();
            return 1;
        }

        client(&ProxySocket, serv);
    }
#pragma clang diagnostic pop
}
