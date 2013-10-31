/*
** client.c 
*/
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<sys/types.h>

#include<openssl/rsa.h>
#include <openssl/objects.h>
#include<openssl/err.h>
#include<openssl/pem.h>
#include<openssl/evp.h>

#include<netinet/in.h>
#include<sys/socket.h>
#include <arpa/inet.h>
#include<netdb.h>

#include "cli_serv.h"



int main(int argc, char *argv[])
{

	int SockServ, numbytes;

	struct addrinfo hints, *servinfo, *p;

	int rv;
	char s[INET6_ADDRSTRLEN];

	if (argc != 2) {
		fprintf(stderr,"usage: client hostname\n");
		exit(ARG_ERR);
	}

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;

	if ((rv = getaddrinfo(argv[1], PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		exit(ADDRINFO_ERR);
	}

	/* loop through all the results and connect to the first we can*/
	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((SockServ = socket(p->ai_family, p->ai_socktype,
			p->ai_protocol)) == -1) {
			perror("client: socket");
			continue;
		}

		if (connect(SockServ, p->ai_addr, p->ai_addrlen) == -1) {
			close(SockServ);
			perror("client: connect");
			continue;
		}
		break;
	}

	if (p == NULL) {
		fprintf(stderr, "client: failed to connect\n");
		exit(CLIENT_ERR_CONEXION);
	}

	inet_ntop(p->ai_family, (struct sockaddr *)p->ai_addr,s, sizeof s);
	printf("client: connecting to %s\n", s);
	freeaddrinfo(servinfo); 

	char buffer[SIZE_2066];

	if ((numbytes = recv(SockServ, buffer, MAXDATASIZE-1, 0)) == -1) {
		perror("recv");
		exit(CLIENT_ERR_RECV);
	}

	buffer[numbytes] = '\0';
	printf("client: received '%s'\n\n",buffer);


USER_LOOP:
        sleep(0);
	char usr[SIZE_216];
	char pwd[SIZE_216];
        char pwd2[SIZE_216];
        int new_user;

        new_user = 0;
        memset(usr, 0, SIZE_216);
	printf("\n\n\n\nUsuario:");
	scanf("%s",usr);

        if(strncmp("NewUser:", usr, 7) == 0){
                memmove(usr, usr+8, strlen(usr)-7);
                new_user = 1;
                if(strstr(usr, ":") != NULL){
                        printf("No se admiten usuarios con ':'");
                        new_user = 0;
                        goto USER_LOOP;
                }
        }

	printf("\nContraseña:");
	scanf("%s",pwd);

        if(new_user){
                printf("\nRepita la contraseña:");
                scanf("%s", pwd2);
                if(strncmp(pwd, pwd2, SIZE_216-1) != 0)
                        goto USER_LOOP;
        }

        /* create new user with assigned password
         */
        if(new_user){
                char *msg;
                msg = cifra_pwd(usr, pwd);

                char resp[SIZE_216];
                char ya_reg[] = "Ya registrado";

                if((send(SockServ,
                         msg,
                         2048,
                         0)) == -1){
                        perror("send");
                        exit(CLIENT_ERR_SEND);
                }

                if((numbytes = recv(SockServ, resp, SIZE_216, 0)) == -1){
                        perror("recv");
                        exit(CLIENT_ERR_RECV);
                }
                if(strncmp(resp, ya_reg, 13) == 0){
                        printf("Usuario ya registrado, lo siento\n");
                        exit(0);
                }

                printf("OK, usuario nuevo [%s] creado. Haga login otra vez.\n", usr);
                exit(0);
                
        }


	printf("\n\t..........COMPROBANDO.........\n");

	/* enviamos usuario */
	if((send(SockServ,usr,sizeof usr,0)) == -1){
		perror("send");
		exit(CLIENT_ERR_SEND);
	}
	/* comprobamos si el usuario es correcto */
	char resp[SIZE_216];
	char resp1[]="No existe el Usuario";
	char resp2[]="No se ha podido abrir el fichero Shadow";

	if ((numbytes = recv(SockServ,resp,SIZE_216, 0)) == -1){
		perror("recv");
		exit(CLIENT_ERR_RECV);
	}
	if(strcmp(resp,resp1)==0 || strcmp(resp,resp2)==0){
		printf("\nError:%s\n\n",resp);
		exit(SYSTEM_ERROR);
	}

	/*recibimos nonce y salt*/
	char *paquete=(char *) calloc(SIZE_216,1);
	if ((numbytes = recv(SockServ,paquete,SIZE_216, 0)) == -1){
		perror("recv");
		exit(CLIENT_ERR_RECV);
	}

	char *salt;
	char *nonce;
	nonce = strsep(&paquete,":");
	salt = strsep(&paquete,"");

	/*printf("\npwd: %s\n",pwd);
	printf("\nsalt: %s\n",salt);
	printf("\nnonce: %s\n",nonce);
	*/

	char *passcrypted=(char *)calloc(SIZE_256,1);
	passcrypted= crypt(pwd,salt);

	/*printf("\nCrypt(): %s\n",passcrypted);*/
	
	/*leemos clave publica decrypt.pub*/
	int x=0;
	RSA *encrypt;
	ReadDecryptKey(&encrypt);
	if(x != CLIENT_SUCCESS){
		printf("\nError en la lectura de la clave publica\n");
		exit(READ_ERR_PUB_KEY);
	}	

	char *encriptado=(char *)calloc(SIZE_4096,1);

	if (encriptado == NULL){
		printf("\nError: Incapaz de asignar memoria a encriptado\n");
		exit(NO_MEMORY_ASSIGN);		
	}

	char *toencrypt=(char *) calloc(SIZE_4096,1);

	if (toencrypt == NULL){
		printf("\nError: Incapaz de asignar memoria a toencrypt\n");
		exit(NO_MEMORY_ASSIGN);		
	}

	snprintf(toencrypt,SIZE_4096,"%s:%s",nonce,passcrypted);

	int y;

	y=RSA_public_encrypt(strlen(toencrypt),(char *)toencrypt,(u_char *)encriptado,encrypt,RSA_PKCS1_OAEP_PADDING);

	if (y == -1){
		ERR_print_errors_fp(stderr);
		printf("\nError al RSA_public_encrypt\n");
		exit (RSA_ERR_ENCRYPT);
	}

	/*printf("\nRSAencripted: %s\n",encriptado);*/

	char *encriptado64= (char *) calloc((RSA_size(encrypt)*4),1);

        if (encriptado64 == NULL){
		printf("\n Incapaz de asignar memoria a encriptado64\n");
		exit(NO_MEMORY_ASSIGN);		
	}	
	
	y = b64_ntop(   (u_char *)encriptado,RSA_size(encrypt),encriptado64,(RSA_size(encrypt)*4));
	if (y == -1){
		printf("\nError al b64_ntop\n");
		exit(B64_ERR);		
	}


	/*printf("\nLa clave cifrada en base64 es:\n");
	  printf("%s\n",encriptado64);
	*/

	/* enviamos el base64(RSA_decrypt(nonce;crypt(salt,passwd)))*/
	if((send(SockServ,encriptado64,SIZE_B64,0)) == -1){
		perror("send");
		exit(CLIENT_ERR_SEND);
	}

	/*recibimos respuesta e iniciamos el ECHO*/
	if ((numbytes = recv(SockServ,buffer,SIZE_216, 0)) == -1){
		perror("recv");
		exit(CLIENT_ERR_RECV);
	}

ECHO_LOOP:
        sleep(0);

	char salir[]="exit";
	char comp1[]="Login CORRECTO";
	char comp2[]="Login INCORRECTO";
        char newpwd[]="newpass:";
	if(strcmp(buffer,comp1)==0){
		printf("\n%s\n\n",buffer);
		printf("\t\tECHO\n\n");
		while(1){
                        memset(buffer, 0, SIZE_2066);
			printf("\n\n\n\nEcho:");
			scanf("%s",buffer);
                        if(strncmp(buffer, newpwd, 8) == 0){
                                char *string = buffer;
                                char *token = strsep(&string, ":");
                                char *msg = cifra_pwd(usr, string);
                                printf("[%s]:[%s]\n", usr, string);
                                send(SockServ, msg, strlen(msg), 0);
                                goto RCV;
                        }
                        

			if((send(SockServ,buffer,strlen(buffer),0)) == -1){
				perror("send");
				exit(CLIENT_ERR_SEND);
			}
	
			if( strcmp(buffer,salir)== 0 ){
				printf("Te has desconectado\n\n");
				break;
			}
                RCV:
			if ((numbytes = recv(SockServ, buffer, SIZE_2066, 0)) == -1){
				perror("recv");
				exit(CLIENT_ERR_RECV);
			}
	
			buffer[numbytes] = '\0';
			printf("ECHOServer: %s\n",buffer);
		}
	
	}
	else
	printf("\n%s\n",buffer);
	
	close(SockServ);
return CLIENT_SUCCESS;
}




int ReadDecryptKey(RSA **encrypt)
{

	FILE *fp2;
	fp2= fopen("decrypt.pub","r");
	
	if(fp2==NULL){
		printf("Error abriendo el archivo decrypt.pub");
		exit(FILE_ERR_OPENNING);
	}

	fseek(fp2, 0, SEEK_SET);

	if((*encrypt=RSA_new())==NULL)
		printf("error");

	OpenSSL_add_all_algorithms();
	PEM_read_RSA_PUBKEY(fp2,encrypt,NULL,NULL);
	fclose(fp2);

return CLIENT_SUCCESS;
}




void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
		return &(((struct sockaddr_in*)sa)->sin_addr);
	}
return &(((struct sockaddr_in6*)sa)->sin6_addr);
}


char *cifra_pwd(char *usr, char *pwd){
                // esto es un copiar-y-pegar, reutilizar
                /*leemos clave publica decrypt.pub*/
                char salt[16];
                memcpy(salt, "$6$", 3);
                RAND_pseudo_bytes(salt+3,8);
                int i;
                for(i=0; i<8; i++)
                        salt[i+3] = 65+abs(salt[i+3]%24);
                salt[i+3]='$';
                salt[i+4]=0;
                char *passcrypted=(char *)calloc(SIZE_256,1);
                passcrypted= crypt(pwd,salt);

                int x=0;
                RSA *encrypt;
                ReadDecryptKey(&encrypt);
                if(x != CLIENT_SUCCESS){
                        printf("\nError en la lectura de la clave publica\n");
                        exit(READ_ERR_PUB_KEY);
                }	

                char *encriptado=(char *)calloc(SIZE_4096,1);

                if (encriptado == NULL){
                        printf("\nError: Incapaz de asignar memoria a encriptado\n");
                        exit(NO_MEMORY_ASSIGN);		
                }

                char *toencrypt=(char *) calloc(SIZE_4096,1);

                if (toencrypt == NULL){
                        printf("\nError: Incapaz de asignar memoria a toencrypt\n");
                        exit(NO_MEMORY_ASSIGN);		
                }

                snprintf(toencrypt,SIZE_4096,"%s",passcrypted);

                int y;

                y=RSA_public_encrypt(strlen(toencrypt),(char *)toencrypt,(u_char *)encriptado,encrypt,RSA_PKCS1_OAEP_PADDING);

                if (y == -1){
                        ERR_print_errors_fp(stderr);
                        printf("\nError al RSA_public_encrypt\n");
                        exit (RSA_ERR_ENCRYPT);
                }

                /*printf("\nRSAencripted: %s\n",encriptado);*/

                char *encriptado64= (char *) calloc((RSA_size(encrypt)*4),1);

                if (encriptado64 == NULL){
                        printf("\n Incapaz de asignar memoria a encriptado64\n");
                        exit(NO_MEMORY_ASSIGN);		
                }	
	
                y = b64_ntop(   (u_char *)encriptado,RSA_size(encrypt),encriptado64,(RSA_size(encrypt)*4));
                if (y == -1){
                        printf("\nError al b64_ntop\n");
                        exit(B64_ERR);		
                }

                char *msg;

                msg = (char *)calloc(strlen(usr)
                                     + 10
                                     +strlen(encriptado64)
                                     +10, 1);
                if(msg == NULL){
                        printf("Incapaz de asignar memoria a msg\n");
                        exit(NO_MEMORY_ASSIGN);
                }

                sprintf(msg,
                         "%s:%s%s",
                         usr,
                         salt,
                         encriptado64);

                return(msg);
}
