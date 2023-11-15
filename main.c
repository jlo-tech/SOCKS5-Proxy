#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>
#include <unistd.h>

#include <fcntl.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/types.h>
#include <sys/socket.h>

#define SOCKS_VERSION 0x05

#define SOCKS_BACKLOG 10
#define SOCKS_PORT "1080"
#define SOCKS_HOST "127.0.0.1"

#define SOCKS_METHOD_NO_AUTH_REQUIRED 	0x00
#define SOCKS_METHOD_GSSAPI 		0x01
#define SOCKS_METHOD_USERNAME_PASSWORD 	0x02
#define SOCKS_METHOD_IANA_ASSIGNED 	0x03
#define SOCKS_METHOD_RESERVED 		0x80
#define SOCKS_METHOD_NOT_ACCEPTABLE 	0xff

#define SOCKS_ADDRESS_TYPE_IPv4 	0x01
#define SOCKS_ADDRESS_TYPE_DOMAINNAME 	0x03
#define SOCKS_ADDRESS_TYPE_IPv6 	0x04

#define SOCKS_REPLY_SUCCEEDED 			0x00
#define SOCKS_REPLY_SERVER_FAILURE 		0x01
#define SOCKS_REPLY_CONNECTION_NOT_ALLOWED 	0x02
#define SOCKS_REPLY_NETWORK_UNREACHABLE 	0x03
#define SOCKS_REPLY_HOST_UNREACHABLE 		0x04
#define SOCKS_REPLY_CONNECTION_REFUSED 		0x05
#define SOCKS_REPLY_TTL_EXPIRED 		0x06
#define SOCKS_REPLY_COMMAND_NOT_SUPPORTED 	0x07
#define SOCKS_REPLY_ADDRESS_TYPE_NOT_SUPPORTED 	0x08 
#define SOCKS_REPLY_UNASSIGNED 			0x09

/**
 * 
 * NOTE: version should be set to SOCKS_VERSION throughout all methods
 *
 */


/* Client */

uint8_t* client_packet_connect(uint8_t version, uint8_t nmethods, uint8_t* methods) 
{
	uint8_t *buf = (uint8_t*)malloc(2 + nmethods);
	
	buf[0] = version;
	buf[1] = nmethods;

	memcpy(&buf[2], methods, nmethods * sizeof(uint8_t));

	return buf;
} 

uint8_t* client_packet_request(uint8_t version, uint8_t command, uint8_t address_type, uint8_t* destination_address, uint16_t destination_port)
{
    int address_length_additive;
    switch (address_type) {
        case SOCKS_ADDRESS_TYPE_IPv4:
            address_length_additive = 4;
            break;
        
        case SOCKS_ADDRESS_TYPE_DOMAINNAME:
            address_length_additive = 1 + destination_address[0];
            break;
            
        case SOCKS_ADDRESS_TYPE_IPv6:
            address_length_additive = 16;
            break;
            
        default:
            address_length_additive = 0;
            break;
    }
    
	// Calculate packet length
    size_t packet_len = 6 + address_length_additive;

	uint8_t *buf = (uint8_t*)malloc(packet_len);

	buf[0] = version;
	buf[1] = command;
	buf[2] = 0x00;
	buf[3] = address_type;

	memcpy(&buf[4], destination_address, address_length_additive);

	buf[4 + (size_t)address_length_additive] = (htons(destination_port) >> 8) & 0xFF;
	buf[5 + (size_t)address_length_additive] = (htons(destination_port) >> 0) & 0xFF;

	return buf;
}

/* Server */
uint8_t* server_packet_connect_response(uint8_t version, uint8_t method)
{
	uint8_t *buf = (uint8_t*)malloc(2);

	buf[0] = version;
	buf[1] = method;

	return buf;
}

uint8_t* server_packet_reply(uint8_t version, uint8_t reply, uint8_t address_type, uint8_t* bind_address, uint16_t bind_port)
{
    int address_length_additive;
    switch (address_type) {
        case SOCKS_ADDRESS_TYPE_IPv4:
            address_length_additive = 4;
            break;
        
        case SOCKS_ADDRESS_TYPE_DOMAINNAME:
            address_length_additive = 1 + bind_address[0];
            break;
            
        case SOCKS_ADDRESS_TYPE_IPv6:
            address_length_additive = 16;
            break;
            
        default:
            address_length_additive = 0;
            break;
    }
    
    size_t packet_len = 6 + address_length_additive;
	
	uint8_t *buf = (uint8_t*)malloc(packet_len);

	buf[0] = version;
	buf[1] = reply;
	buf[2] = 0x00;
	buf[3] = address_type;

	memcpy(&buf[4], bind_address, address_length_additive);

	buf[4 + (size_t)address_length_additive] = (htons(bind_port) >> 8) & 0xFF;
	buf[5 + (size_t)address_length_additive] = (htons(bind_port) >> 0) & 0xFF;

	return buf;
}

void server_handle_connection(int fd, struct sockaddr addr)
{
    // Make socket blocking again
    int flags = fcntl(fd, F_GETFL, 0);
    fcntl(fd, F_SETFL, flags ^ O_NONBLOCK);
    
    // TODO
    while(1)
    {
        int rc = 0, tc = 0;
        
        // Read connect request
        uint8_t version = 0;
        uint8_t nmethods = 0;
        uint8_t methods[255];
        
        read(fd, &version, 1);
        read(fd, &nmethods, 1);
        do {
            rc += read(fd, &methods + rc, nmethods - rc);
        } while (rc < nmethods);
        
        // Send connect reponse
        // Currently we only support no authentication method
        uint8_t *connect_reponse_buf = server_packet_connect_response(SOCKS_VERSION, SOCKS_METHOD_NO_AUTH_REQUIRED);
        
        tc = 2;
        do {
            tc -= write(fd, connect_reponse_buf + (2 - tc), tc);
        } while (tc > 0);
        
        // Receive client request
        uint8_t request_buf[5];
        
        rc = 5;
        do {
            rc -= read(fd, request_buf + (5 - rc), rc);
        } while (rc > 0);
        
        int atype;
        int alength;
        switch (request_buf[3])
        {
            case SOCKS_ADDRESS_TYPE_IPv4:
                rc = 4;
                alength = rc;
                atype = SOCKS_ADDRESS_TYPE_IPv4;
                break;
            case SOCKS_ADDRESS_TYPE_DOMAINNAME:
                rc = request_buf[4];
                alength = rc + 1;
                atype = SOCKS_ADDRESS_TYPE_DOMAINNAME;
                break;
            case SOCKS_ADDRESS_TYPE_IPv6:
                rc = 16;
                alength = rc;
                atype = SOCKS_ADDRESS_TYPE_IPv6;
                break;
            default:
                break;
        }
        
        uint8_t *request_address_port_buf = (uint8_t*)malloc(rc + 2);
        do {
            rc -= read(fd, request_address_port_buf, rc);
        } while (rc > 0);
        

        // Connect to remote server...
        int remote_sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
        
        switch (atype)
        {
            case SOCKS_ADDRESS_TYPE_IPv4: {
                // Build IPv4 address
                struct sockaddr_in raddr;
                raddr.sin_family = AF_INET;
                raddr.sin_addr.s_addr = (request_address_port_buf[4] << 24) | (request_address_port_buf[5] << 16) | (request_address_port_buf[6] << 8) | (request_address_port_buf[7] << 0);
                raddr.sin_port = (request_address_port_buf[8] << 8) | (request_address_port_buf[9] << 0);
                // Connect...
                int err = connect(remote_sock, (struct sockaddr*)&raddr, sizeof(raddr));
                // Send response...
                uint8_t *request_reply_buf;
                // Check status
                if(err < 0)
                {
                    // Return error (reply)
                    request_reply_buf = server_packet_reply(SOCKS_VERSION, SOCKS_REPLY_HOST_UNREACHABLE, atype, (uint8_t*)&raddr, (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1]));
                }
                else
                {
                    // Return success (reply)
                    request_reply_buf = server_packet_reply(SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, atype, (uint8_t*)&raddr, (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1]));
                }
            } break;
                
            case SOCKS_ADDRESS_TYPE_DOMAINNAME: {
                // Extract address
                char *addr_str = (char*)malloc(alength);
                memcpy(addr_str, &request_address_port_buf[5], alength);
                addr_str[alength] = '\0';
                // Build address
                struct sockaddr_in raddr;
                raddr.sin_family = AF_INET;
                raddr.sin_addr.s_addr = inet_addr(addr_str);
                raddr.sin_port = (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1] << 0);
                // Connect...
                int err = connect(remote_sock, (struct sockaddr*)&raddr, sizeof(raddr));
                // Send response...
                uint8_t *request_reply_buf;
                // Check status
                if(err < 0)
                {
                    // Return error (reply)
                    request_reply_buf = server_packet_reply(SOCKS_VERSION, SOCKS_REPLY_HOST_UNREACHABLE, atype, (uint8_t*)&raddr, (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1]));
                }
                else
                {
                    // Return success (reply)
                    request_reply_buf = server_packet_reply(SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, atype, (uint8_t*)&raddr, (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1]));
                }
            } break;

            case SOCKS_ADDRESS_TYPE_IPv6: {
                struct sockaddr_in6 raddr;
                raddr.sin6_family = AF_INET6;
                memcpy(&raddr.sin6_addr, &request_address_port_buf[4], 16);
                raddr.sin6_port = (request_address_port_buf[20] << 8) | (request_address_port_buf[21] << 0);
                // Connect...
                int err = connect(remote_sock, (struct sockaddr*)&raddr, sizeof(raddr));
                // Send response...
                uint8_t *request_reply_buf;
                // Check status
                if(err < 0)
                {
                    // Return error (reply)
                    request_reply_buf = server_packet_reply(SOCKS_VERSION, SOCKS_REPLY_HOST_UNREACHABLE, atype, (uint8_t*)&raddr, (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1]));
                }
                else
                {
                    // Return success (reply)
                    request_reply_buf = server_packet_reply(SOCKS_VERSION, SOCKS_REPLY_SUCCEEDED, atype, (uint8_t*)&raddr, (request_address_port_buf[4 + alength] << 8) | (request_address_port_buf[4 + alength + 1]));
                }
            } break;
            
            default:
                break;
        }
        
        // Actually send appropriate response
        int reply_length = 4 + alength + 2;
        do {
            reply_length -= send(fd, request_address_port_buf, reply_length, 0);
        } while (reply_length > 0);
        
        // Free memory
        free(request_address_port_buf);
        
        // TODO: Forward incoming data and responses
    }
}

uint8_t server_run()
{
	// Create socket
	int sockfd = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);

	// Allow reusing the port
	int opt = 1;
	setsockopt(sockfd, SOL_SOCKET, SO_REUSEADDR, (int*)&opt, sizeof(opt));

	// Fill address info struct
	struct addrinfo hints;
	memset(&hints, 0, sizeof(hints));

	hints.ai_family = AF_INET;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_protocol = IPPROTO_TCP;

	struct addrinfo *sock_addr;
	getaddrinfo(SOCKS_HOST, SOCKS_PORT, &hints, &sock_addr);	

	// Make socket nonblocking
	int flags = fcntl(sockfd, F_GETFL, 0);
	fcntl(sockfd, F_SETFL, flags | O_NONBLOCK);

	// Bind socket
	bind(sockfd, sock_addr->ai_addr, sock_addr->ai_addrlen);
	
	// Listen on socket
	listen(sockfd, SOCKS_BACKLOG);
    
	// Accept and handle connections (nonblocking)
	while(1)
	{
        // Accept new connection if there is one
        struct sockaddr client_addr;
		socklen_t clientaddr_len = sizeof(struct sockaddr);
		int clientfd = accept(sockfd, &client_addr, &clientaddr_len);
		// Add sockaddr to queue
        if(clientfd >= 0)
        {
            pid_t pid = fork();
            if(pid == 0)
            {
                // handle connection in child
                server_handle_connection(clientfd, client_addr);
            }
            // parent continues with accepting connections...
        }
        // Sleep
        usleep(100);
	}
    
	close(sockfd);

	return 0;
}

int main(int argc, char* argv[])
{
    server_run();
    
	return 0;
}
