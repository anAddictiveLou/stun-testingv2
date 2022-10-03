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
#include <pthread.h>
#include "stun.h"
#include "nat_traversal.h"


int n,
	sockfd,
	keep_mapping_condition,
	verbose;

int main(int argc, char *argv[])
{
    if (argc != 4) {
		printf("\nusage: ./stun_client <server_ip> <server_port> <local_port>\n");
		exit(EXIT_FAILURE);
	} 

	struct sockaddr_in servaddr, remote_addr, localaddr;
	char return_ip[32]; 
	unsigned short return_port=0;
	char* stun_server_ip = argv[1];
	uint16_t stun_server_port = atoi(argv[2]);
	uint16_t stun_client_port = atoi(argv[3]);
	
	
    // create socket
    sockfd = socket(AF_INET, SOCK_DGRAM, 0); 
	if(sockfd == -1) handle_error("socket()\n");

	// server
    memset(&servaddr, 0, sizeof(struct sockaddr_in));
    servaddr.sin_family = AF_INET;
    servaddr.sin_port = htons(stun_server_port);	
	inet_pton(AF_INET, stun_server_ip, &servaddr.sin_addr.s_addr);

    // host address
    memset(&localaddr, 0, sizeof(struct sockaddr_in));
    localaddr.sin_family = AF_INET;
    localaddr.sin_port = htons(stun_client_port);

	/*Biding host address to socket*/
	bind(sockfd, (struct sockaddr *)&localaddr, sizeof(struct sockaddr));

	n = stun_implement(sockfd, servaddr, return_ip, &return_port);
	if (n!=0) 
		handle_selffunc_error("\nstun_implement() fail!\n");
	else {
		char local_ip_addr[LOCAL_ADDR_LEN];
		keep_mapping_condition = 1;
		printf("\nlocal address <ip> <port> : %s %d\n", get_localaddr(local_ip_addr, LOCAL_ADDR_LEN), stun_client_port);
		printf("public address <ip> <port> : %s %d\n", return_ip, return_port);
	}

	pthread_t keep_connect_thread;
    if (pthread_create(&keep_connect_thread, NULL, keep_connect, &servaddr) != 0)
        handle_error("thread_read");

	/*Connect to remote*/
	char remote_ip[30];
	int remote_port;
    memset(&remote_addr, 0, sizeof(struct sockaddr_in));
    remote_addr.sin_family = AF_INET;
    remote_addr.sin_port = htons(remote_port);	
	inet_pton(AF_INET, remote_ip, &remote_addr.sin_addr.s_addr);

	printf("\nConnecting to... <remote_ip> <remote_port> : ");
	scanf("%s %d", remote_ip, &remote_port);
	printf("\nWaiting for connection...\n");


	n = udp_hole_punching(sockfd, remote_addr);
	if (n == -1) {
		/*handle symmetric nat traversal*/
		struct peer_info remote_peer;
		memset(&remote_peer, 0, sizeof(struct peer_info));
		strcpy(remote_peer.ip, inet_ntoa(remote_addr.sin_addr));
		remote_peer.port = remote_addr.sin_port;
		connect_to_symmetric_nat(NULL, 0, remote_peer);
		//handle_selffunc_error("\nudp_hole_punching() fail!\n");
	}
	else udp_session_communicate(sockfd, remote_addr);
	
	if (pthread_join(keep_connect_thread, NULL) == -1)
        handle_error("keep_connect()");
	close(sockfd);

	return 0;
}
