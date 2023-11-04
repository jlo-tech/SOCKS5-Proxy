#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdint.h>

#include <arpa/inet.h>

#define SOCKS_VERSION 0x05

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
	// Calculate packet length
	size_t packet_len = 6 + destination_address[0] + 1;

	uint8_t *buf = (uint8_t*)malloc(packet_len);

	buf[0] = version;
	buf[1] = command;
	buf[2] = 0x00;
	buf[3] = address_type;

	memcpy(&buf[4], destination_address, destination_address[0] + 1);

	buf[4 + (size_t)destination_address + 1] = (htons(destination_port) >> 8) & 0xFF;
	buf[4 + (size_t)destination_address + 2] = (htons(destination_port) >> 0) & 0xFF;

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
	size_t packet_len = 6 + bind_address[0] + 1;
	
	uint8_t *buf = (uint8_t*)malloc(6 + bind_address[0] + 1);

	buf[0] = version;
	buf[1] = reply;
	buf[2] = 0x00;
	buf[3] = address_type;

	memcpy(&buf[4], bind_address, bind_address[0] + 1);

	buf[4 + (size_t)bind_address + 1] = (htons(bind_port) >> 8) & 0xFF;
	buf[4 + (size_t)bind_address + 2] = (htons(bind_port) >> 0) & 0xFF;

	return buf;
}


int main(int argc, char* argv[])
{

	return 0;
}
