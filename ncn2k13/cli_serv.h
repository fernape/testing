
/* cliente*/
#define ARG_ERR 101
#define ADDRINFO_ERR 102

#define CLIENT_ERR_CONEXION 110
#define CLIENT_ERR_RECV 111
#define CLIENT_ERR_SEND 112
#define CLIENT_SUCCESS 0

#define NO_MEMORY_ASSIGN 200

#define RSA_ERR_ENCRYPT 1000
#define B64_ERR 1001

#define FILE_ERR_OPENNING 500

#define SIZE_216 216
#define SIZE_256 256
#define PORT "3490" // the port client will be connecting to
#define SIZE_4096 4096
#define MAXDATASIZE 216 // max number of bytes we can get at once
// get sockaddr, IPv4 or IPv6:


/*servidor*/
#define SOCKOPT_ERR 103
#define SIGACTION_ERR 104

#define SERV_ERR_BIND 113
#define SERV_ERR_LISTEN 114
#define SERV_ERR_SEND 115
#define SERV_ERR_RECV 116
#define SERV_ERR_CONEXION 117
#define SERV_SUCCESS 0

#define READ_ERR_PUB_KEY 5000

#define SIBYL_ERR_NONCE 10000
#define SIBYL_ERR_RESPONSE 10001
#define SERV_ERR_SENDTO_SIBYL 10002
#define SIBYL_ERR_VERIFICATION 10003

#define SIBYL_PORT "9999"
#define SIBYL_IP "127.0.0.1"

#define LEN_PORT 4
#define LEN_IP 16

/* nonce + salt + ":" */
#define SIZE_NONSALT 34
#define SIZE_M 17
#define RAND_NUM 8
#define SIZE_B64 4096
#define SIZE_SALT 16
#define SIZE_NONCE 16
#define SIZE_2066 2066
#define SIZE_SIBYL_RESPONSE 4096
/*numero aleatorio 'm' + el pwd del fichero shadow en MD5 + el B64(RSA(NONCE;CRYPT(SALT,PWD)))*/
#define SIZE_1390 1390
#define SIZE_SHA1 20
#define SIZE_PTR_FILE 4096
#define PORT "3490" // the port users will be connecting to
#define BACKLOG 10 // how many pending connections queue will hold
#define SIZE_512 512

#define SYSTEM_ERROR 3000



void sigchld_handler(int s);
void *get_in_addr(struct sockaddr *sa);

char *cifra_pwd(char *usr, char *pwd);

int existeUSR(char *usr);
int verificarUSR(char *usr,char *salt,char *passmd5);
int ReadSignKey(RSA **sign);

int ReadSignKey(RSA **encrypt);
void *get_in_addr(struct sockaddr *sa);
