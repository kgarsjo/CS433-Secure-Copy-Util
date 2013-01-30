#include <arpa/inet.h>
#include <fcntl.h>
#include <errno.h>
#include <gcrypt.h>
#include <netdb.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------- //
	Golbal Variables
// -------------------------------- */
const int MAX_CHUNK= 1024;
const int HMAC_SIZE= 16;

/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void 	decrypt(char*, char*, int, int, int);
void 	gcryptInit();
char*	getPassword();
char*	genMAC(char*, int, char*, int, char*, int);
void	printUsage();
int 	setupSocket(char*);

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {

	int 	daemonFlag		= 1;
	int 	localFlag		= 0;
	char 	*filename		= (char*) malloc(sizeof(char) * MAX_CHUNK);
	char	*password		= NULL;
	char 	*port			= NULL;
	int 	fdin			= -1;

	gcryptInit();

	if (argc == 1) {
		printUsage();
		exit(-1);
	}

	// Fetch all arguments and flags
	opterr= 0;
	int c;
	while ((c= getopt(argc, argv, "l:")) != -1) {
		switch(c) {
			case 'l':
				localFlag= 1;
				daemonFlag= 0;
				char *darg= optarg;
				strcpy(filename, darg);
				break;
			case '?':
			default:
				printUsage();
				exit(1);
		}
	}

	if (daemonFlag) {
		port= argv[optind];
	}


	// ---------------- Daemon mode operation ---------------- //
	if (daemonFlag) {

		// Prepare a server socket for connections
		fdin= setupSocket(port);
		if (fdin == -1) {
			perror("[ERROR] Problems occurred while binding server socket: ");
			exit(3);
		}

		
		// Indefinitely loop as daemon...
		while(1) {

			// Wait for and accept incoming client connections
			printf("Waiting for connections.\n");
			int res= listen(fdin, 100);
			if (res == -1) {
				perror("[ERROR] Problem occurred while listening for connections: ");
				exit(4);
			}

			int clientfd= accept(fdin, NULL, NULL);
			printf("Inbound file. ");

			password= getPassword();

			
			// Receive filename info before ciphertext, open ciphertex output file
			uint32_t fnamelen;
			res= recv(clientfd, &fnamelen, sizeof(uint32_t), 0);
			if (res == -1) {
				perror("[ERROR] Problem occurred while recv'ing filename: ");
				exit(5);
			}
			char *resultname= (char*) malloc(fnamelen + 1);
			res= recv(clientfd, resultname, fnamelen, 0);
			resultname[fnamelen]= '\0'; 

			res= access(resultname, F_OK);
			if (res == 0) {
				printf("[ERROR] Output file already exists. Aborting...\n");
				exit(6);
			}

			int fdout= open(resultname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
			if (fdout == -1) {
				perror("[ERROR] Problem occurred while opening output file: ");
				exit(7);
			}


			// Decrypt and cleanup
			decrypt(resultname, password, clientfd, fdout, 1);

			close(clientfd);
			close(fdout);
			free(resultname);
		}


	// ---------------- Local mode operation ---------------- //
	} else if (localFlag) {

		// Determine result filename, open both input ciphertext
		// and output plaintext files for reading/writing
		char *resultname= (char*) malloc(strlen(filename) - 2);
		strncpy(resultname, filename, strlen(filename) - 3);

		fdin= open(filename, O_RDONLY);
		if (fdin == -1) {
			perror("[ERROR] Problem occurred while opening ciphertext: ");
			exit(8);
		}

		int fdout= open(resultname, O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
		if (fdout == -1) {
			perror("[ERROR] Problem occurred while opening output file: ");
			exit(9);
		}	

		password= getPassword();
		
		// Decrypt and clean up
		decrypt(resultname, password, fdin, fdout, 0);
		close(fdout);
		free(resultname);

	}

	// Final cleanup, only reached if running in local mode
	close(fdin);
	free(filename);
	free(password);

	return 0;
}


/* ---------------------------------------------------------------- //
	void decrypt - Decrypts a given file, writing the resulting
		plaintext locally

	char*	outfilename	: The name of the output file
	char*	password	: The user-submitted password
	int		fdin		: The ciphertext's file descriptor
	int		fdout		: The plaintext output file descriptor
	int		daemonFlag	: Whether ciphertext is local (0) or over
							the network (>=1)
// ---------------------------------------------------------------- */
void decrypt(char *outfilename, char *password, int fdin, int fdout, int daemonFlag) {
	gcry_cipher_hd_t handle;
	gcry_error_t	 error;
	const size_t 	KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	const size_t 	BLKLEN= gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);

	const char 		*salt= "saltyEnough?";
	const char 		*iv=   "inivec\0\0\0\0\0\0\0\0\0\0";

	char 	*inbuf=		(char*) malloc(sizeof(char) * MAX_CHUNK + HMAC_SIZE);
	char 	*key=		(char*) malloc(sizeof(char) * KEYLEN);
	char 	*outbuf=	(char*) malloc(sizeof(char) * MAX_CHUNK + HMAC_SIZE);

	int bytesread= 0;	// Measures bytes read per iteration
	int byteswrote= 0;	// Measures bytes wrote per iteration
	int bytestotal= 0;	// Measures total bytes, including HMAC and plaintext


	// Generate key using PBKDF2
	error= gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 12, 4096, KEYLEN, key);
	if (error) {
		printf("[ERROR] Problem occurred while generating key: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(10);
	}

	// Set the handle and key
	error= gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
	if (error) {
		printf("[ERROR] Problem occurred while setting up handle: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(11);
	}

	error= gcry_cipher_setkey(handle, key, KEYLEN);
	if (error) {
		printf("[ERROR] Problem occurred while setting key: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(12);
	}
	
	error= gcry_cipher_setiv(handle, iv, BLKLEN);
	if (error) {
		printf("[ERROR] Problem occurred while setting IV: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(13);
	}


	// Loop until client stops sending
	while (1) {
		memset(inbuf, 0, MAX_CHUNK + HMAC_SIZE);
		memset(outbuf, 0, MAX_CHUNK);
		
		if (daemonFlag) {
			bytesread= recv(fdin, inbuf, MAX_CHUNK + HMAC_SIZE, 0);
			if (bytesread == -1 || bytesread == 0) {
				break;
			}
		} else {
			bytesread= read(fdin, inbuf, MAX_CHUNK + HMAC_SIZE);
			if (bytesread == -1 || bytesread == 0) {
				break;
			}
		}


		// Decrypt and check HMAC
		error= gcry_cipher_decrypt(handle, outbuf, bytesread, inbuf, bytesread);
		if (error) {
			printf("[ERROR] Problem occurred while decrypting: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
			exit(14);
		}

		int msglen= bytesread - HMAC_SIZE;
		char *HMAC= &outbuf[msglen];
		char *digest= genMAC(outbuf, msglen, NULL, 0, key, KEYLEN);
		int res= strncmp(HMAC, digest, HMAC_SIZE);
		if (res != 0) {
			printf("[ERROR] MAC digests do not match!\n");
		}

		// Handle padding at end
		int padamt= 0;
		if (msglen % MAX_CHUNK != 0) {
			padamt= outbuf[msglen - 1];
		}
		
		byteswrote= write(fdout, outbuf, msglen - padamt);
		bytestotal += byteswrote;
		printf("read %d bytes, wrote bytes %d\n", bytesread, msglen);

		free(digest);

	} // End decryption while-loop


	if (bytesread == 0) {	
		printf("Successfully received and decrypted %s.uo to %s (%d bytes written)\n\n\n", outfilename, outfilename, bytestotal);
	}

	free(inbuf);
	free(key);
	free(outbuf);
}


/* ---------------------------------------------------------------- //
	void gcryptInit - Compartmentalizes the libgcrypt setup calls
		necessary to encrypt/decrypt
// ---------------------------------------------------------------- */
void gcryptInit() {
	if (!gcry_check_version(GCRYPT_VERSION)) {
		printf("%s\n", "Incorrect gcrypt version!");
		exit(15);
	}

	gcry_control(GCRYCTL_SUSPEND_SECMEM_WARN);
	gcry_control(GCRYCTL_INIT_SECMEM, 16384, 0);
	gcry_control(GCRYCTL_RESUME_SECMEM_WARN);
	gcry_control(GCRYCTL_INITIALIZATION_FINISHED, 0);
}


/* ---------------------------------------------------------------- //
	char* genMAC - Generates, returns a ptr to, and optionally
		stores an HMAC for a given buffer

	char* 	inbuf	: The buffer to generate an HMAC for.
	int		ilen	: The length of the above inbuf.
	char 	*dest	: The destination to store the HMAC. If dest is
						NULL, the HMAC will not be stored, only
						returned by the function via ptr.
	int		dlen	: The length of the above dest buf. If dest is
						NULL, this will be ignored.
	char*	key		: The key to generate the HMAC with.
	int		klen	: The length of the above key

	returns a pointer to the generated HMAC.
	NOTE: If the caller opts not to provide a dest, then it is
		the caller's responsibility to free the returned char ptr.
// ---------------------------------------------------------------- */
char* genMAC(char *inbuf, int ilen, char *dest, int destlen, char *key, int klen) {
	gcry_md_hd_t handle;
	gcry_error_t error;
	int digestlen= gcry_md_get_algo_dlen(GCRY_MD_SHA256);

	// Set the HMAC handle and key
	error= gcry_md_open(&handle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (error) {
		printf("[ERROR] Problem occurred while opening MD handle: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(16);
	}

	error= gcry_md_setkey(handle, key, klen);
	if (error) {
		printf("[ERROR] Problem occurred while setting HMAC key: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(17);
	}

	// Add buffer contents and finalize hash
	gcry_md_write(handle, inbuf, ilen);

	error= gcry_md_final(handle);
	if (error) {
		printf("[ERROR] Problem occurred while generating HMAC: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(18);
	}

	unsigned char *digest= gcry_md_read(handle, GCRY_MD_SHA256);
	if (digest == NULL) {
		printf("[ERROR] Problem occurred while reading HMAC\n");
		exit(19);
	}

	if (dest == NULL) {
		char *digestcpy= (char*) malloc(HMAC_SIZE);
		strncpy(digestcpy, (char*)digest, HMAC_SIZE);
	
		gcry_md_close(handle);
		return digestcpy;
	}

	// Copy digest to the appropriate allocated dest buffer, as space allows
	if (destlen < digestlen) {
		strncpy(dest, (char*)digest, destlen);
	} else {
		strncpy(dest, (char*)digest, digestlen);
	}

	gcry_md_close(handle);

	return dest;
}


/* ---------------------------------------------------------------- //
	void gcryptInit - Compartmentalizes the libgcrypt setup calls
		necessary to encrypt/decrypt
// ---------------------------------------------------------------- */
char* getPassword() {
	// Prompt for password
	char *password= NULL;
	printf("Password: ");
	size_t size= MAX_CHUNK;
	int res= getline(&password, &size, stdin);
	if (res == -1) {
		perror("getline:");
		exit(2);
	}

	return password;
}


/* ---------------------------------------------------------------- //i
	void printUsage - Displays command-line format and options
		for running uoenc
// ---------------------------------------------------------------- */
void printUsage() {
	printf("%s\n", "Usage: uodec <port> [-l <input file>]");
}


/* ---------------------------------------------------------------- //
	int setupSocket - Binds a TCP server socket for listening to
		incoming client connections
	
	char*	port	: The port to listen on

	returns	: The file descriptor on success
			: -1 on failure

	NOTE: Most of this method has been appropriated from Beej's
		Guide to Network Programming.
		See http://beej.us/guide/bgnet for mor details.
// ---------------------------------------------------------------- */
int setupSocket(char *port) {
	int result= 0;
	int sockfd= -1;

	// Setup hints
	struct addrinfo hints, *servinfo;
	memset(&hints, 0, sizeof hints);
	hints.ai_family= AF_INET;
	hints.ai_socktype= SOCK_STREAM;
	hints.ai_flags= AI_PASSIVE;

	// Fetch address info struct
	if ((result= getaddrinfo(NULL, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
		return -1;
	}

	// Create socket
	sockfd= socket(servinfo->ai_family, servinfo->ai_socktype, servinfo->ai_protocol);
	if (sockfd == -1) {
		perror("socket: ");
		return -1;
	}

	if ((bind(sockfd, servinfo->ai_addr, servinfo->ai_addrlen)) == -1) {
		perror("bind: ");
		return -1;
	}

	return sockfd;
}
