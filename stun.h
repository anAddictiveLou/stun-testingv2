#define MAX_SIZE_BUF 300
#define STUN_HDR_LEN 20 
#define STUN_ATTR_HDR_LEN 4
#define STUN_BINDING_METHOD 0X0001
#define STUN_RESPONE_SUCCESS 0x0101
#define XOR_MAPPED_ADDR_ATTR 0x0020
#define MAGIC_COOKIE 0x2112A442
#define LOCAL_ADDR_LEN 50
#define handle_error(msg) \
	do { perror(msg); exit(EXIT_FAILURE); } while (0)

#define handle_selffunc_error(msg) \
    do { printf(msg); exit(EXIT_FAILURE); } while (0)


int stun_implement(int sockfd, struct sockaddr_in servaddr, char * return_ip, unsigned short * return_port);
char* get_localaddr(char* info, int n);
int udp_hole_punching(int sockfd, struct sockaddr_in remote_addr);
struct sockaddr_in set_remote();
void udp_session_communicate(int sockfd, struct sockaddr_in remote_addr);
void *keep_connect(void *servaddr);
