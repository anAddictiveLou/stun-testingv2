#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <ifaddrs.h>
#include <netdb.h>
#include <stdbool.h>
#include <fcntl.h>
#include "stun.h"
extern int n, sockfd, keep_mapping_condition;

int stun_implement(int sockfd, struct sockaddr_in servaddr, char* return_ip, unsigned short* return_port)
{
	unsigned char buf[MAX_SIZE_BUF];
    unsigned char stun_request[STUN_HDR_LEN];    

	useconds_t RTOtime = 1000 * 500; //1mili = 1000u
	int stun_method;
	short attr_type;
	short attr_length;
	short port;
	short stun_msg_length;


    // first bind 
	* (short *)(&stun_request[0]) = htons(STUN_BINDING_METHOD);    // stun_method rfc 5389
	* (short *)(&stun_request[2]) = htons(0x0000);    //msg_length: do not contain payload
	* (int *)(&stun_request[4])   = htonl(MAGIC_COOKIE);

	*(int *)(&stun_request[8]) = htonl(0x63c7117e);   // transacation ID 
	*(int *)(&stun_request[12])= htonl(0x0714278f);
	*(int *)(&stun_request[16])= htonl(0x5ded3221);

	while(1)
	{
		//printf("Send data ...\n");
		n = sendto(sockfd, stun_request, sizeof(stun_request), 0, (const struct sockaddr *) &servaddr, sizeof(servaddr)); 
		if (n == -1) 
			handle_error("sendto()\n");

		memset(buf, 0, sizeof(buf));
		n = recvfrom(sockfd, buf, 300, 0, NULL, 0);
		switch (n)
		{
			case -1:
				handle_error("revcfrom_stunsrv()");
			case 0:
				usleep(RTOtime);
				RTOtime*=2;
				if (RTOtime / (1000 * 500) == 128)	//after trying to send STUN request 7 times
					handle_selffunc_error("\nRTO: Time Out\n");
				continue;
			default:
				goto out_wloop;
		}
		out_wloop: break;
	}
	
	if (*(short *)(&buf[0]) == htons(STUN_RESPONE_SUCCESS));
	{

		stun_msg_length = htons(*(short *)(&buf[2]));	//Message Length = 48 
		int i = STUN_HDR_LEN;
			/*Tìm kiếm XOR MAPPED ATTRIBUTE trong Respone msg*/
        	while(i<sizeof(buf))	
       	 	{
				attr_type = htons(*(short *)(&buf[i]));
				attr_length = htons(*(short *)(&buf[i+2]));
				if (attr_type == XOR_MAPPED_ADDR_ATTR)
				{
					port = ntohs(*(short *)(&buf[i+6]));
					port ^= 0x2112;

						/*Get public endpoint of STUN client*/ 
					*return_port = port;
					sprintf(return_ip,"%d.%d.%d.%d",buf[i+8]^0x21,buf[i+9]^0x12,buf[i+10]^0xA4,buf[i+11]^0x42);
					break;
				}
				/* Sau mỗi vòng loop sẽ duyệt qua một attribute trong STUN respone
				Biến i trỏ sang attribute kế tiếp với i = i + 4 + attr_length
				Trong đó:	4 - STUN Attribute header length
							attr_length - STUN Attribute Value length			*/
				i += (STUN_ATTR_HDR_LEN + attr_length);	
        	}
	}

	return 0;
}

char* get_localaddr(char *info, int n)
{
	struct ifaddrs *addresses;
	struct in_addr *tmpAddrPtr;
	if (getifaddrs(&addresses) == -1) 
		handle_error("getifaddrs()\n");

	struct ifaddrs *address = addresses;
	while(address) 
	{
		int family = address->ifa_addr->sa_family;
		if (family == AF_INET) {
			tmpAddrPtr=&((struct sockaddr_in *)address->ifa_addr)->sin_addr;
			/*Covert uint32_t IP address at tmpAddrPtr to char pointed by info*/
			inet_ntop(AF_INET, tmpAddrPtr, info, n);
			if (strcmp(info, "127.0.0.1") != 0) 
				break;
				memset(info, 0, n);
		}
		address = address->ifa_next;
	}
	freeifaddrs(addresses);
	return info;
}

int udp_hole_punching(int sockfd, struct sockaddr_in remote_addr)
{
	char buf[100] = "/0";


	/*UDP Hole Punching*/
	int sendCheck = 0;
	static int count = 10;
	char temp[30] = "Hole Punching\n";

	/*Set socket to non-blocking socket*/
	int opts;
	opts = fcntl(sockfd,F_GETFL);
    if (opts < 0) {
        perror("fcntl(F_GETFL)");
        exit(EXIT_FAILURE);
    }
	int new_opts = opts;
    new_opts = (new_opts | O_NONBLOCK);
    if (fcntl(sockfd,F_SETFL,new_opts) < 0) {
        perror("fcntl(F_SETFL)");
        exit(EXIT_FAILURE);
    }

	while (count > 0)
	{	
		memcpy(buf, temp, sizeof(temp));
		sendCheck = sendto(sockfd, buf, sizeof(buf), 0, (const struct sockaddr *) &remote_addr, sizeof(remote_addr));
		if (sendCheck > 0) {
			count--;
			printf("\nTry to send %d UDP packet to remote addr.\n", 10 - count);
		}
		memset(buf, 0, sizeof(buf));
		n = recvfrom(sockfd, buf, 300, 0, NULL, 0);
		if (n > 0) {
			memset(buf, 0, sizeof(buf));
			printf("\nRecv the first UDP packet from remote addr successfully.\n");
				
			//Clear socket buffer
			while(read(sockfd, buf, sizeof(buf)) > 0) {
					strcpy(buf, ""); //attempt to erase all old values
					fflush(stdout);
				}

			//Set socket to blocking mode
			if (fcntl(sockfd, F_SETFL, opts) < 0) {
				perror("fcntl(F_SETFL)");
				exit(EXIT_FAILURE);
			}
			printf("\nUDP Hole Punching Successful.\nStart to communicate..\n");
			return 0;
		}
		sleep(1);
	}
	return -1;

}

struct sockaddr_in set_remote(void)
{
	/*Connect to remote*/
	struct sockaddr_in remote_addr;
	char remote_ip[30];
	int remote_port;
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote_port);	
	inet_pton(AF_INET, remote_ip, &remote_addr.sin_addr.s_addr);

	printf("\nConnecting to... <remote_ip> <remote_port> : ");
	scanf("%s %d", remote_ip, &remote_port);
	printf("\nWaiting for connection...\n");
	return remote_addr;
}

void udp_session_communicate(int sockfd, struct sockaddr_in remote_addr)
{
	char buf[100] = "/0";
	while (1)
	{
		fflush(stdin);
		printf("\nSend to remote: ");
		fgets(buf, 100, stdin);
		sendto(sockfd, buf, sizeof(buf), 0, (const struct sockaddr *) &remote_addr, sizeof(remote_addr));
		if (n == -1) 
			handle_error("send_to_after_hole-punc():"); 
		memset(buf, 0, sizeof(buf));
		printf("*****************************");

		printf("\nRecv from remote: ");
		recvfrom(sockfd, buf, 300, 0, NULL, 0);
		printf("%s", buf);
		sleep(1);
		memset(buf, 0, sizeof(buf));
	}
	
}

void *keep_connect(void *servaddr)
{
	int k;
	struct sockaddr_in servaddr_t = *(struct sockaddr_in*)servaddr; 
	char keep_mapping_msg[4] = "keep";
	while(1)
	{
		k = sendto(sockfd, keep_mapping_msg, sizeof(keep_mapping_msg), 0, (const struct sockaddr*) &servaddr_t, sizeof(struct sockaddr)); 
		if (k == -1)
			handle_error("\nsendto_keepmapping(): ");
		//if (keep_mapping_condition == 1)
		sleep(1);
	} 
}