#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>

#pragma comment(lib, "ws2_32.lib") // Link Winsock library

#define PORT 8080
#define BUFFER_SIZE 1024

// XOR Encryption/Decryption function
void xor_encrypt_decrypt(char *message, char *key, int message_len, int key_len)
{
    for (int i = 0; i < message_len; i++)
    {
        if (message[i] == key[i % key_len])
        {
            continue;
        }
        int res = message[i] ^ key[i % key_len];
        if (res == EOF || res == '\n' || res == '\0' || res == 26)
        {
            continue;
        }
        message[i] ^= key[i % key_len];
    }
}

int main()
{
    WSADATA wsa;
    SOCKET server_sock, client_sock;
    struct sockaddr_in server_addr, client_addr;
    char buffer[BUFFER_SIZE];
    char key[BUFFER_SIZE];
    char client_name[BUFFER_SIZE];
    char host_name[BUFFER_SIZE];

    // Ask for host name
    printf("Enter your name : ");
    fgets(host_name, BUFFER_SIZE, stdin);
    host_name[strlen(host_name) - 1] = '\0'; // Remove newline

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    // 1. Create socket
    server_sock = socket(AF_INET, SOCK_STREAM, 0);
    if (server_sock == INVALID_SOCKET)
    {
        printf("Socket creation failed. Error Code: %d\n", WSAGetLastError());
        WSACleanup();
        return 1;
    }

    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    // 2. Bind socket to address
    if (bind(server_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) == SOCKET_ERROR)
    {
        printf("Bind failed. Error Code: %d\n", WSAGetLastError());
        closesocket(server_sock);
        WSACleanup();
        return 1;
    }

    // Retrieve and display the server's IP address
    char host_ip[NI_MAXHOST];
    gethostname(host_ip, NI_MAXHOST); // Get the hostname

    struct hostent *host_entry;
    host_entry = gethostbyname(host_ip); // Get host info by name

    if (host_entry == NULL)
    {
        printf("Unable to get host IP address.\n");
    }
    else
    {
        // Convert IP from binary to string format
        struct in_addr **addr_list = (struct in_addr **)host_entry->h_addr_list;
        printf("Host IP address: %s\n", inet_ntoa(*addr_list[0])); // Print the first IP address
    }

    while (1)
    {
        // 3. Listen for connections
        listen(server_sock, 1);
        printf("Server listening on port %d...\n", PORT);

        // 4. Accept client connection
        int client_len = sizeof(client_addr);
        client_sock = accept(server_sock, (struct sockaddr *)&client_addr, &client_len);
        if (client_sock == INVALID_SOCKET)
        {
            printf("Accept failed. Error Code: %d\n", WSAGetLastError());
            closesocket(server_sock);
            WSACleanup();
            return 1;
        }
        printf("Client connected!\n");

        // 5. Receive client's name
        int name_len = recv(client_sock, client_name, BUFFER_SIZE - 1, 0);
        if (name_len > 0)
        {
            client_name[name_len] = '\0'; // Null-terminate the client's name
            // Strip newline or carriage return characters
            for (int i = name_len - 1; i >= 0; i--)
            {
                if (client_name[i] == '\n' || client_name[i] == '\r')
                {
                    client_name[i] = '\0';
                }
                else
                {
                    break;
                }
            }
            printf("Client's name is: %s\n", client_name);
        }

        // 6. Receive XOR key from client
        int key_len = recv(client_sock, key, BUFFER_SIZE, 0);
        if (key_len > 0)
        {
            // Remove any newline or carriage return characters
            key[key_len] = '\0'; // Null-terminate the received data
            // Strip newline or carriage return characters
            for (int i = key_len - 1; i >= 0; i--)
            {
                if (key[i] == '\n' || key[i] == '\r')
                {
                    key[i] = '\0';
                }
                else
                {
                    break;
                }
            }
            printf("Encryption key received: %s\n", key);
        }
        // print the client's IP
        char *client_ip = inet_ntoa(client_addr.sin_addr);
        printf("Client's IP is : %s\n", client_ip);

        // 7. Send Server's name
        send(client_sock, host_name, strlen(host_name), 0);

        // 8. Chat loop (receive and send messages)
        printf("\n====== Chatting with %s======\n", client_name);
        while (1)
        {
            memset(buffer, 0, BUFFER_SIZE);

            // Receive encrypted message from client
            int len = recv(client_sock, buffer, BUFFER_SIZE, 0);
            if (len <= 0)
            {
                printf("Client disconnected\n");
                break;
            }

            // Decrypt the message using XOR
            xor_encrypt_decrypt(buffer, key, len, strlen(key));
            if (strcmp(buffer, "EXIT") == 0)
            {
                printf("Client has left the chat.\n");
                break;
            }
            printf("\n(%s): %s\n", client_name, buffer);

            // Get response from server user
            memset(buffer, 0, BUFFER_SIZE);
            printf("\nYou (%s): ", host_name);
            fgets(buffer, BUFFER_SIZE, stdin);
            buffer[strlen(buffer) - 1] = '\0'; // Remove newline character

            // Encrypt the response using XOR
            xor_encrypt_decrypt(buffer, key, strlen(buffer), strlen(key));

            // Send encrypted message to client
            send(client_sock, buffer, strlen(buffer), 0);
        }
    }

    // 9. Close sockets and cleanup
    closesocket(client_sock);
    closesocket(server_sock);
    WSACleanup();

    return 0;
}
