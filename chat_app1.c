#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <winsock2.h>
#include <ws2tcpip.h>
#include <ctype.h>

#pragma comment(lib, "ws2_32.lib") // Link Winsock library

#define PORT 8080
#define BUFFER_SIZE 1024

WSADATA wsa;
SOCKET client_sock;
SOCKET server_sock;
struct sockaddr_in server_addr, client_addr;
char buffer[BUFFER_SIZE];
char key[BUFFER_SIZE];
char client_name[BUFFER_SIZE];
char name[BUFFER_SIZE];
char host_ip[BUFFER_SIZE];
char host_name[BUFFER_SIZE];
char file_line[BUFFER_SIZE];

// XOR Encryption/Decryption function
void xor_encrypt_decrypt(char *message, char *key, int message_len, int key_len)
{
    for (int i = 0; i < message_len; i++)
    {
        // if message character is same as the key character don't encrypt
        //  since that creates \0
        //  these two if statements are drawbacks of using XOR
        if (message[i] == key[i % key_len])
        {
            continue;
        }
        int res = message[i] ^ key[i % key_len];
        // if result of XOR operation is EOF, newline, null char or SUB char don't encrypt
        if (res == EOF || res == '\n' || res == '\0' || res == 26)
        {
            continue;
        }
        message[i] ^= key[i % key_len];
    }
}

// Function to display the chat history
void display_history(const char *host_n, const char *key)
{
    FILE *file = fopen(host_n, "r");
    if (!file)
    {
        printf("No history found for Host: %s\n", host_n);
        return;
    }

    char line[BUFFER_SIZE];
    printf("\n====== Chat History with %s ======\n", host_name);
    while (fgets(line, BUFFER_SIZE, file))
    {
        // get a line from file, each line is one person's message
        // decrypt and display
        line[strlen(line) - 1] = '\0'; // remove newline
        xor_encrypt_decrypt(line, key, strlen(line), strlen(key));
        printf("\n%s\n", line);
    }
    fclose(file);
}

int main()
{

    // Ask for name
    printf("Enter your name : ");
    fgets(name, BUFFER_SIZE, stdin);
    name[strlen(name) - 1] = '\0'; // Remove newline

    // Initialize Winsock
    if (WSAStartup(MAKEWORD(2, 2), &wsa) != 0)
    {
        printf("Failed. Error Code: %d\n", WSAGetLastError());
        return 1;
    }

    while (1)
    {
        // Display the 3 options menu
        printf("\n======= MENU =======\n");
        printf("1) Connect to start chatting\n");
        printf("2) Wait for a connection\n");
        printf("3) Display chat history\n");
        printf("4) Exit\n");
        printf("Select an option: ");
        char option = getchar();
        getchar(); // Consume newline

        if (option == '1')
        {
            strcpy(client_name, name);
            // Get host's IP address
            printf("Enter the host's IP address: ");
            fgets(host_ip, BUFFER_SIZE, stdin);
            host_ip[strlen(host_ip) - 1] = '\0'; // Remove newline

            // Get XOR key
            printf("Enter the XOR secret key: ");
            fgets(key, BUFFER_SIZE, stdin);
            key[strlen(key) - 1] = '\0'; // Remove newline

            // 1. Create client socket
            client_sock = socket(AF_INET, SOCK_STREAM, 0);
            if (client_sock == INVALID_SOCKET)
            {
                printf("Socket creation failed. Error Code: %d\n", WSAGetLastError());
                continue;
            }

            // setting the host ip address, network protocol and port
            server_addr.sin_family = AF_INET;
            server_addr.sin_port = htons(PORT);
            server_addr.sin_addr.s_addr = inet_addr(host_ip);

            // 2. Connect to server
            if (connect(client_sock, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
            {
                printf("Connection failed. Error Code: %d\n", WSAGetLastError());
                closesocket(client_sock);
                continue;
            }
            printf("Connected to the server!\n");

            // 3. Send client's name and key to host
            send(client_sock, client_name, strlen(client_name), 0);
            // key is a combination of the entered text and client name
            strcat(key, client_name);
            send(client_sock, key, strlen(key), 0);

            // 4. Recieve Host name
            int name_len = recv(client_sock, host_name, BUFFER_SIZE - 1, 0);
            if (name_len > 0)
            {
                host_name[name_len] = '\0'; // Null-terminate the client's name
                // Strip newline or carriage return characters
                for (int i = name_len - 1; i >= 0; i--)
                {
                    if (host_name[i] == '\n' || host_name[i] == '\r')
                    {
                        host_name[i] = '\0';
                    }
                    else
                    {
                        break;
                    }
                }
                printf("Host's name is: %s\n", host_name);
            }

            // Open log file for this host with the host's name
            FILE *file = fopen(host_name, "a");
            if (!file)
            {
                printf("Could not open file to save chat history.\n");
                closesocket(client_sock);
                continue;
            }

            // Chat loop
            printf("\n====== Chatting with %s ======\n", host_name);
            while (1)
            {
                // buffer holds in incoming and outgoing message
                // file_line holds copy of in/out message with (name) : to be written to file
                // clearing data of both
                memset(file_line, 0, BUFFER_SIZE);
                memset(buffer, 0, BUFFER_SIZE);

                // taking input from client for sending a message
                printf("\nYou (%s): ", client_name);
                fgets(buffer, BUFFER_SIZE, stdin);
                buffer[strlen(buffer) - 1] = '\0'; // Remove newline

                // if client enters EXIT go back to loop
                if (strcmp(buffer, "EXIT") == 0)
                {
                    printf("Exiting chat...\n");
                    break;
                }

                // adding (name) : and the message in file_line
                strcpy(file_line, "(");
                strcat(file_line, client_name);
                strcat(file_line, "): ");
                strcat(file_line, buffer);
                // encrypting file_line content
                xor_encrypt_decrypt(file_line, key, strlen(file_line), strlen(key));
                strcat(file_line, "\n");
                // storing the message in the file
                fprintf(file, "%s", file_line);
                fflush(file);

                // this time we're encrypting buffer directly
                xor_encrypt_decrypt(buffer, key, strlen(buffer), strlen(key));
                // sending encrypted message
                send(client_sock, buffer, strlen(buffer), 0);

                // clearing buffer so it can be used again
                memset(buffer, 0, BUFFER_SIZE);
                // Receive and decrypt response from host-
                int len = recv(client_sock, buffer, BUFFER_SIZE, 0);
                if (len <= 0)
                {
                    printf("Server disconnected.\n");
                    break;
                }

                // decrypt buffer, it has response from host
                xor_encrypt_decrypt(buffer, key, len, strlen(key));
                buffer[len] = '\0'; // Null-terminate
                // clearing file_line
                memset(file_line, 0, BUFFER_SIZE);
                // same as before adding the (name) : and the message to file_line
                strcpy(file_line, "(");
                strcat(file_line, host_name);
                strcat(file_line, "): ");
                strcat(file_line, buffer);
                // re-encrypting the file_line which has the response from host, because we want to store
                //  encrypted text in file
                xor_encrypt_decrypt(file_line, key, strlen(file_line), strlen(key));
                strcat(file_line, "\n");
                // store in file
                fprintf(file, "%s", file_line);
                fflush(file);

                printf("\n(%s): %s\n", host_name, buffer);
            }

            // Close socket and file
            fclose(file);
            closesocket(client_sock);
            closesocket(server_sock);
            WSACleanup();
        }
        else if (option == '2')
        {
            strcpy(host_name, name);

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

            int yes = 1;
            if (setsockopt(server_sock, SOL_SOCKET, SO_REUSEADDR,
                           (void *)&yes, sizeof(yes)) < 0)
            {
                printf("\nsock opt error");
            }

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
                        printf("Continue waiting for connection?\n");
                        printf("1. Yes\n");
                        printf("2. No\n");
                        printf("Enter: ");
                        char opt = getchar();
                        getchar(); // Consume newline
                        if (opt == '1')
                        {
                            break;
                        }
                        else if (opt == '2')
                        {
                            goto end;
                        }
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
            closesocket(client_sock);
            closesocket(server_sock);
            WSACleanup();
        }
        else if (option == '3')
        {
            // Get host's name address for history
            memset(host_name, 0, BUFFER_SIZE);
            printf("Enter the person's name to view history: ");
            fgets(host_name, BUFFER_SIZE, stdin);
            host_name[strlen(host_name) - 1] = '\0'; // Remove newline

            // Get XOR key
            printf("Enter the XOR secret key: ");
            fgets(key, BUFFER_SIZE, stdin);
            key[strlen(key) - 1] = '\0'; // Remove newline

            // Display chat history
            strcat(key, name);
            display_history(host_name, key);
        }
        else if (option == '4')
        {
            printf("Exiting the client...\n");
            break;
        }
        else
        {
            printf("Invalid option. Please try again.\n");
        }
    end:
        closesocket(client_sock);
        closesocket(server_sock);
        WSACleanup();
    }

    WSACleanup();
    return 0;
}
