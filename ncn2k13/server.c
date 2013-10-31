/*
** server.c -- a stream socket server demo
*/
#include<stdio.h>
#include<stdlib.h>
#include<unistd.h>
#include<errno.h>
#include<string.h>
#include<sys/types.h>
#include<sys/time.h>
#include<sys/wait.h>
#include<syslog.h>
#include<signal.h>

#include <openssl/sha.h>
#include <openssl/rsa.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/err.h>

#include <netinet/in.h>
#include <netdb.h>
#include <arpa/inet.h>
#include <sys/socket.h>

#include "cli_serv.h"



int main(void)
{
	RSA *sign;
	int x=0;

	// leemos clave publica sign.pub
	x=ReadSignKey(&sign);
	if(x != SERV_SUCCESS){
		printf("\nError en la lectura de la clave publica\n");
		exit(READ_ERR_PUB_KEY);
	}		

	int SockClient, new_fd,numbytes; // listen on SockClient, new connection on new_fd

	struct addrinfo hints, *servinfo, *p;
	struct sockaddr_storage their_addr; // connector's address information

	socklen_t sin_size;

	struct sigaction sa;

	int yes=1;
	char s[INET6_ADDRSTRLEN];
	int rv;

	memset(&hints, 0, sizeof hints);
	hints.ai_family = AF_UNSPEC;
	hints.ai_socktype = SOCK_STREAM;
	hints.ai_flags = AI_PASSIVE; // use my IP

	if ((rv = getaddrinfo(NULL, PORT, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
		return ADDRINFO_ERR;
	}

	/*loop through all the results and bind to the first we can*/

	for(p = servinfo; p != NULL; p = p->ai_next) {
		if ((SockClient = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
			perror("server: socket");
			continue;
		}

		if (setsockopt(SockClient, SOL_SOCKET, SO_REUSEADDR, &yes,sizeof(int)) == -1) {
			perror("setsockopt");
			exit(SOCKOPT_ERR);
		}

		if (bind(SockClient, p->ai_addr, p->ai_addrlen) == -1) {
			close(SockClient);
			perror("server: bind");
			continue;
		}
	break;
	}


	if (p == NULL) {
		fprintf(stderr, "server: failed to bind\n");
		return SERV_ERR_BIND;
	}

	freeaddrinfo(servinfo); 

	if (listen(SockClient, BACKLOG) == -1) {
		perror("listen");
		exit(SERV_ERR_LISTEN);
	}
	/* reap all dead processes*/
	sa.sa_handler = sigchld_handler; 
	sigemptyset(&sa.sa_mask);
	sa.sa_flags = SA_RESTART;

	if (sigaction(SIGCHLD, &sa, NULL) == -1) {
		perror("sigaction");
		exit(SIGACTION_ERR);
	}

	printf("\n\nserver: waiting for connections...\n");
	/*main accept() loop*/
	while(1) { 
		sin_size = sizeof their_addr;
		new_fd = accept(SockClient, (struct sockaddr *)&their_addr, &sin_size);

		if (new_fd == -1) {
			perror("accept");
			continue;
		}
		/*this is the child process*/
		if (!fork()){
			close(SockClient);

			inet_ntop(their_addr.ss_family,
			get_in_addr((struct sockaddr *)&their_addr),s, sizeof s);

			printf("\nserver: got connection from Client %s\n", s);	

			if (send(new_fd, "Hello!", 6, 0) == -1){
				perror("send");
				close(new_fd);
				exit(SERV_ERR_SEND);
			}
			//Preparamos conexión con sibila

			printf("\n\n.....CONECTANDOSE CON LA SIBILA(%s).....\n",s);

			char *ip = (char *) calloc(32, sizeof(char *));

		        if (ip == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}	

			char *port = (char *) calloc (5, sizeof(char *));

		        if (port == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			strncpy(port,SIBYL_PORT,LEN_PORT);
			strncpy(ip,SIBYL_IP,LEN_IP);

			int SockSibyl, numbytes;
			struct addrinfo hints, *servinfo, *p;
			int rv;
			char s[INET6_ADDRSTRLEN];

			memset(&hints, 0, sizeof hints);
			hints.ai_family = AF_UNSPEC;
			hints.ai_socktype = SOCK_STREAM;
	
			if ((rv = getaddrinfo(ip, port, &hints, &servinfo)) != 0) {
				fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(rv));
				return ADDRINFO_ERR;
			}

			/* loop through all the results and connect to the first we can*/
			for(p = servinfo; p != NULL; p = p->ai_next) {
				if ((SockSibyl = socket(p->ai_family, p->ai_socktype,p->ai_protocol)) == -1) {
					perror("Server: socket");
					continue;
				}

				if (connect(SockSibyl, p->ai_addr, p->ai_addrlen) == -1) {
					close(SockSibyl);
					perror("Server: connect");
					continue;
				}
			break;
			}

			if (p == NULL) {
				fprintf(stderr, "Server: failed to connect\n");
				return SERV_ERR_CONEXION;
			}

			inet_ntop(p->ai_family, (struct sockaddr *)p->ai_addr,s, sizeof s);
			freeaddrinfo(servinfo);
	
			printf("\nConexion con la sibyla establecida\n");

			/* recibimos usuario */
			char *usr=(char *)calloc(SIZE_2066,1);
		        if (usr == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			if((numbytes=recv(new_fd,usr,2048,0))==-1){
				perror("recv");
				exit(SERV_ERR_RECV);
			}

                        /* si el usuario es "X:Y", enviamos la sal
                           y terminamos */
                        
                        if(strstr(usr, ":") != NULL){
                                char *newusr;
                                char *newpwd;
                                newusr = strsep(&usr, ":");
                                newpwd = usr;

                                if(existeUSR(newusr)){
                                        send(new_fd, "Ya registrado", 13, 0);
                                        exit(SERV_ERR_RECV);
                                }

                                if(addUSR(newusr, newpwd)){
                                        printf("Oups, no puedo añadir el usuario\n");
                                        exit(-1);
                                };
                                send(new_fd, "New user added.\n", 10, 0);
                                exit(0);

                        }


			/* recibimos nonce */
			u_int num_read = 0;
			char *chain=(char *)calloc(SIZE_1390,1);
		        if (chain == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			while((num_read = read (SockSibyl, chain, SIZE_216)) == 0);

			if (num_read == -1) {
				printf("\nError nonce \n");
				exit (SIBYL_ERR_NONCE);
			}else
			printf("\nNonce recibido\n");

			/*Se comprueba que la cadena recibida sea correcta.*/
			if(chain[num_read-1] != '@') {
				printf("\nEl nonce incorrecto.\n");
				exit (SIBYL_ERR_RESPONSE);
			}
			/*Elimino la @ para poder trabajar con el*/
			char *nonce=(char *) calloc(SIZE_NONCE,sizeof(char));
		        if (nonce == NULL){
				printf("\nIncapaz de asignar memoria a nonce\n");
				exit(NO_MEMORY_ASSIGN);		
			}	
			strncpy(nonce,chain,num_read-1);

			/* 
			* enviamos al cliente
			* la salt y el md5 correspondiente
			* del fichero shadow
			*/

			char *salt=(char *) calloc(SIZE_SALT,1);
		        if (salt == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}
	
			char *passmd5=(char*)calloc(SIZE_512,1);
		        if (passmd5 == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			char *paquete=(char *)calloc(SIZE_NONSALT,1);
		        if (paquete == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			/* obtenemos la salt y el md5 */
			int usr_call;
			char resp[SIZE_216];
			if((usr_call = verificarUSR(usr,salt,passmd5))!=0){
				if(usr_call == -2){
					snprintf(resp,SIZE_216,"%s","No existe el Usuario");
					if (send(new_fd, resp, SIZE_216, 0) == -1){
						perror("send");
						close(new_fd);
						exit(SERV_ERR_SEND);
					}
					printf("\nNo existe el Usuario\n");
					exit(-2);
				}	

				if(usr_call == FILE_ERR_OPENNING){
					snprintf(resp,SIZE_216,"%s","No se ha podido abrir el fichero Shadow");
					if (send(new_fd, resp, SIZE_216, 0) == -1){
						perror("send");
						close(new_fd);
						exit(SERV_ERR_SEND);
					}
					printf("\nNo se ha podido abrir el fichero Shadow\n");
					exit(FILE_ERR_OPENNING);
				}

			}else	
			snprintf(resp,SIZE_216,"%s","OK");
			 if (send(new_fd, resp, SIZE_216, 0) == -1){
				perror("send");
				close(new_fd);
				exit(SERV_ERR_SEND);
			}
	

			snprintf(paquete,SIZE_NONSALT,"%s:%s",nonce,salt);

			if (send(new_fd, paquete, SIZE_216, 0) == -1){
				perror("send");
				close(new_fd);
				exit(SERV_ERR_SEND);
			}

			/* generamos un número aleatorio m */
			char *m=(char *) calloc(SIZE_M,1);
			if (m == NULL){
				printf("\nError: Incapaz de asignar memoria a m\n");
				exit(NO_MEMORY_ASSIGN);		
			}	
			u_char newnonce[RAND_NUM+1];
			RAND_bytes(newnonce, RAND_NUM);
			int count;
			for(count = 0; count < RAND_NUM; count++)-sprintf((m)+count*2, "%02X", newnonce[count]);

			/*recibimos el base64(RSA_decrypt(nonce;crypt(salt,passwd))) del cliente */
			char *encriptado64=(char *)calloc(SIZE_B64,1);
	        	if (encriptado64 == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			if((numbytes=recv(new_fd,encriptado64,SIZE_B64,0))==-1){
				perror("recv");
				exit(SERV_ERR_RECV);
			}

			snprintf(chain,SIZE_1390,"[];%s;%s;%s@@",m,passmd5,encriptado64);
			printf("Enviando a la Sibila: %s\n\n",chain);
	
			int y=0;
		
			y=write(SockSibyl,chain,strlen(chain));
			if(y==-1) {
				printf("Error al enviar el mensaje\n");
				exit (SERV_ERR_SENDTO_SIBYL);
			}	
			else printf("\nEnvio_OK\n");

			chain=(char*) realloc(chain,SIZE_2066*sizeof(char));
	        	if (chain == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			printf("\nObteniendo respuesta de la sibyla.....");

			/* recibimos respuesta de la sibila */
			char *buffer=(char *)calloc(SIZE_SIBYL_RESPONSE,1);
		        if (buffer == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

			bzero(buffer, SIZE_SIBYL_RESPONSE);

			while((num_read=read(SockSibyl,buffer,SIZE_SIBYL_RESPONSE)) == 0);
			/*printf("\nRespuesta: [%s]\n",buffer);*/
			if(num_read==-1){
				printf("Error al leer de la sibyla\n");
				exit (SIBYL_ERR_VERIFICATION);
			}
			else printf("OK\n");

			if(buffer[num_read-1] != '@') {
				printf("\nLa respuesta no es valida\n");
				exit (SIBYL_ERR_RESPONSE);
			}

			char *response=(char *) calloc(SIZE_SIBYL_RESPONSE,1);
	        	if (response == NULL){
				printf("\nIncapaz de asignar memoria \n");
				exit(NO_MEMORY_ASSIGN);		
			}

		        if (response == NULL){
				printf("\nError: Incapaz de asignar memoria a response\n");
				exit(NO_MEMORY_ASSIGN);		
			}

			strncpy(response,buffer,num_read-1);
			printf("\nRespuesta: %s\n",response);

			char *part[2];
			part[0]=strsep(&response,";");
			part[1]=strsep(&response,"");

			/* sha1 genera resumenes de 20 bytes */
			char *sha1_m = (char *) calloc(SIZE_SHA1, sizeof(char));
		        if (sha1_m == NULL){
				printf("\nError: Incapaz de asignar memoria a sha1_m\n");
				exit(NO_MEMORY_ASSIGN);		
			}
			SHA1((u_char *)part[0], strlen(part[0]), (u_char*)sha1_m);

			char *firma=(char *) calloc (RSA_size(sign)+1,sizeof(char));
		        if (firma == NULL){
				printf("\nError: Incapaz de asignar memoria a firma\n");
				exit(NO_MEMORY_ASSIGN);		
			}	

			/* Se decodifica el base64*/
			x=b64_pton(part[1],(u_char *) firma, RSA_size(sign)+1);

			/* Se intenta verificar */
			y=RSA_verify(NID_sha1,(u_char *)sha1_m,SIZE_SHA1,(u_char *)firma,RSA_size(sign),sign);
			if(y==-1){
				printf("\nError al verificar\n");
				ERR_print_errors_fp(stderr);
				exit (NO_MEMORY_ASSIGN);
			}

			/* La primera parte del mensaje recibido de la sibyla contiene la 
			 * respuesta al intento de login y es del estilo m:X, siendo Y==0 
			 * en caso negativo o Y==1 en caso positivo.
			 */
			char resp1[]="Login CORRECTO";
			char resp2[]="Login INCORRECTO";
			char *token[2];	
			token[0]=strsep(&part[0],":");
			token[1]=strsep(&part[0],"");
			printf("\nAnalizando respuesta.....");
			if(y==1){
				if(!strcmp(token[0],m)){
					if(!strcmp(token[1],"1")){
						printf("%s\n", "Login correcto");
						snprintf(buffer,SIZE_216,"%s",resp1);		
						if((send(new_fd,buffer,SIZE_216,0))==-1){
							perror("send");
							exit(SERV_ERR_SEND);
						}
					}
					else if (!strcmp(token[1],"0")){
						printf("%s\n","Login incorrecto");
						snprintf(buffer,SIZE_216,"%s",resp2);
						if((send(new_fd,buffer,SIZE_216,0))==-1){
							perror("send");
							exit(SERV_ERR_SEND);
						}
					}
				}
				else printf("\n%s\n", "Ha habido algun error durante el proceso");
			}
			else printf("\n%s\n","La firma no es correcta");	

			/* si el cliente se ha hecho login correctamente
			   hacemos echo, si no cerramos la conexion
			*/
			char salir[]="exit";
                        char delme[]="delme.really.";
			char comp1[]="PassWord CORRECTO";
			char comp2[]="PassWord INCORRECTO";
                        char *newp = (char *)calloc(strlen(usr)+2,1);
                        memcpy(newp, usr, strlen(usr));
                        newp[strlen(usr)]=':';
                        printf("comparar con: [%s]\n", newp);
			if(strcmp(buffer,resp1)==0){
				printf("\n\n.........ECHO..........\n");
				while(1){
					if((numbytes=recv(new_fd,buffer,SIZE_2066,0))==-1){
						perror("recv");
						exit(SERV_ERR_RECV);
					}
	
					buffer[numbytes] = '\0';
					printf("\n\nECHO: %s\n",buffer);
					//comprobamos que no se quiera desconectar el cliente escribiendo exit
					if( strcmp(buffer,salir)== 0 ){
						break;
					}

                                        if(strcmp(buffer,delme) == 0){
                                                borraUSR(usr);
                                                send(new_fd, "Usuario borrado.", 17, 0);
                                                break;
                                        }

                                        if(strncmp(buffer, newp, strlen(newp)) == 0){
                                                char *u, *p;
                                                borraUSR(usr);
                                                u=strsep(&buffer, ":");
                                                p=buffer;
                                                addUSR(u, p);
                                                send(new_fd, 
                                                     "Password cambiado.\n",
                                                     20,
                                                     0);
                                                continue;
                                        }

					//printf("\n\n\nEl Cliente a enviado:%s\n",usr);
					if((send(new_fd,buffer,SIZE_216,0))==-1){
						perror("send");
						exit(SERV_ERR_SEND);
					}
				}
			}
		



			printf("\nEl cliente %s se ha desconectado\n\n\n",s);
                        shutdown(new_fd, SHUT_RDWR);
			close(new_fd);
			exit(-1);
		}//fork
	


	close(new_fd); // parent doesn't need this
	}

return SERV_SUCCESS;
}

int borraUSR(char *usr){
        int retval = 0;
        FILE *fichero;
        FILE *copia;
        fichero = fopen("shadow", "a+");
        copia   = fopen("shadow.tmp", "w");
	if(fichero==NULL || copia == NULL){
		printf("Error abriendo el archivo shadow");
                fclose(fichero);
                fclose(copia);
		return(FILE_ERR_OPENNING);
	}
        char *line = (char *)calloc(SIZE_PTR_FILE, 1);
        char *token;
        size_t len = 1024;

        while(!feof(fichero)){
                getline(&line, &len, fichero);
                token=strsep(&line, ":");
                if(strncmp(usr, token, strlen(token)) == 0){
                        continue;
                }
                if(line)
                        fprintf(copia, "%s:%s", token, line);
        }

        fclose(copia);
        fclose(fichero);

        rename("shadow.tmp", "shadow");

}

int addUSR(char *usr, char* pwd){
        int retval = 0;
        FILE *fichero;
        fichero = fopen("shadow", "a+");
	if(fichero==NULL){
		printf("Error abriendo el archivo shadow");
                fclose(fichero);
		return(FILE_ERR_OPENNING);
	}
        
        fseek(fichero, 0, SEEK_END);
        fprintf(fichero, "%s:%s\n", usr, pwd);
        fclose(fichero);
        return(retval);

}

int existeUSR(char *usr){
        int retval = 0;
        FILE *fichero;
        fichero = fopen("shadow", "r");
	if(fichero==NULL){
		printf("Error abriendo el archivo shadow");
		return(FILE_ERR_OPENNING);
	}
        char *line = (char *)calloc(SIZE_PTR_FILE, 1);
        char *token;
        size_t len = 1024;

        while(!feof(fichero)){
                getline(&line, &len, fichero);
                token=strsep(&line, ":");
                if(strncmp(usr, token,strlen(token)) == 0){
                        retval = 1;
                        break;
                }
        }

        fclose(fichero);
        return retval;
}


int verificarUSR(char *usr,char *salt,char *passmd5)
{
	int retval = 0;
	FILE *fichero;

	fichero = fopen("shadow","r");

	if(fichero==NULL){
		printf("Error abriendo el archivo shadow");
		return(FILE_ERR_OPENNING);
	}

	char *file=(char *) calloc(SIZE_PTR_FILE,1);
	char *token[8];
	char comp[SIZE_216];
	size_t len=1024;
	int encontrado=0;

	while(!feof(fichero)){
		getline(&file,&len,fichero);
		token[0]=strsep(&file,":");//Usuario
		snprintf(comp,SIZE_216,"%s",token[0]);
	
		if(strcmp(usr,comp)==0){
			token[1]=strsep(&file,"$");
			token[1]=strsep(&file,"$");
			token[2]=strsep(&file,"$");
			token[3]=strsep(&file,":");
			snprintf(salt,SIZE_216,"$%s$%s$",token[1],token[2]);//Salt
			encontrado = 1;
			break;
		}
	}
	if(encontrado){
		snprintf(passmd5,SIZE_512,"%s",token[3]);
                if(passmd5[strlen(passmd5)-1] == 0x0A)
                        passmd5[strlen(passmd5)-1]=0;
	}else {
		retval = -2;
	}

fclose(fichero);
return (retval);
}




int ReadSignKey(RSA **sign)
{

	FILE *fp2;
	fp2= fopen("sign.pub","r");

	if(fp2==NULL){
		printf("Error abriendo el archivo sign.pub");
		return(FILE_ERR_OPENNING);
	}

	fseek(fp2, 0, SEEK_SET);

	if((*sign=RSA_new())==NULL){
		printf("error");
		return(FILE_ERR_OPENNING);
	}
	OpenSSL_add_all_algorithms();

	PEM_read_RSA_PUBKEY(fp2,sign,NULL,NULL);
	fclose(fp2);

return SERV_SUCCESS;
}




void sigchld_handler(int s)
{
	while(waitpid(-1, NULL, WNOHANG) > 0);
}



/* get sockaddr, IPv4 or IPv6:*/
void *get_in_addr(struct sockaddr *sa)
{
	if (sa->sa_family == AF_INET) {
	return &(((struct sockaddr_in*)sa)->sin_addr);
	}

return &(((struct sockaddr_in6*)sa)->sin6_addr);
}

