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
const int 			MAX_CHUNK= 1024;
const int			HMAC_SIZE= 16;

/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void 	encryptAndSend(char*, char*, int, int, int);
void 	gcryptInit();
char*	genMAC(char*, int, char*, int, char*, int);
void 	printUsage();
int		setupLocal(char*);
int		setupSocket(char*, char*);
void 	test_printKey(char*);

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {
	char *inputFile		= NULL;
	char *outputIP		= (char*) malloc(sizeof(char) * MAX_CHUNK);
	char *outputPort	= (char*) malloc(sizeof(char) * MAX_CHUNK);
	char *password		= NULL;	

	int daemonFlag		= 0;
	int localFlag		= 0;

	int localfd			= -1;
	int sockfd			= -1;

	gcryptInit();

	if (argc == 1) {
		printUsage();
		exit(-1);
	}

	// Fetch all arguments
	opterr= 0;
	int c;
	while ((c= getopt(argc, argv, "ld:")) != -1) {
		switch(c) {
			case 'd':
				daemonFlag= 1;
				char *darg= optarg;
				strcpy(outputIP, strtok(darg, ":"));
				strcpy(outputPort, strtok(NULL, ":"));
				break;
			case 'l':
				localFlag= 1;
				break;
			case '?':
			default:
				printUsage();
				exit(1);
		}
	}

	// Default to local mode if no flags given
	if (!daemonFlag && !localFlag) {
		localFlag= 1;
	}

	// The input file should be the first (and only) flag-unrelated arg
	inputFile= argv[optind];


	// Open the input file
	int fdin= open(inputFile, O_RDONLY);
	if (fdin == -1) {
		printf("[ERROR] Could not open file %s\n", inputFile);
		exit(2);
	}

	// Prompt for password
	printf("Password: ");
	size_t size= MAX_CHUNK;
	int res= getline(&password, &size, stdin);
	if (res == -1) {
		perror("getline:");
		exit(3);
	}

	// Open sending methods and encrypt
	if (localFlag) {
		localfd= setupLocal(inputFile);
		if (localfd == -1) {
			printf("[ERROR] Could not create file %s.uo\n", inputFile);
			exit(4);
		}
	}
	if (daemonFlag) {
		sockfd= setupSocket(outputIP, outputPort);
		if (sockfd == -1) {
			printf("[ERROR] Could not connect to address/port\n");
			exit(5);
		}
	}
	encryptAndSend(inputFile, password, fdin, sockfd, localfd);
	
	if (daemonFlag) {
		printf("Transmitting to %s:%s\n", outputIP, outputPort);
		printf("Successfully received\n");
	}


	// Cleanup File Descriptors and alloc'd memory
	close(fdin);
	close(localfd);
	close(sockfd);

	free(outputIP);
	free(outputPort);
	free(password);

	return 0;
}


/* ---------------------------------------------------------------- //
	void encryptAndSend - Encrypts a given infile, writing the
		resulting ciphertext either locally or to a daemon decrypter
		service.

	char 	*filename	: The original plaintext filename
	char 	*password	: The user-submitted password
	int	 	fdin		: The plaintext's file descriptor
	int		sockfd		: The socket file descriptor for writing to
							the daemon
	int		localfd		: The ciphertext output file descriptor
// ---------------------------------------------------------------- */
void encryptAndSend(char *filename, char *password, int fdin, int sockfd, int localfd) { 

	gcry_cipher_hd_t handle;
	gcry_error_t	 error;
	const size_t 	KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	const size_t 	BLKLEN= gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	
	const char 		*salt= "saltyEnough?";
	const char 		*iv=   "inivec\0\0\0\0\0\0\0\0\0\0";

	char 	*inbuf=  	(char*) malloc(sizeof(char) * MAX_CHUNK + HMAC_SIZE);
	char 	*key= 		(char*) malloc(sizeof(char) * KEYLEN);
	char 	*outbuf= 	(char*) malloc(sizeof(char) * MAX_CHUNK + HMAC_SIZE);

	int 	bytesread= 	0;	// Measures bytes read per iteration
	int 	byteswrote= 0;	// Measures bytes wrote per iteration
	int		bytestotal= 0;	// Measures total bytes, including HMAC and plaintext
	off_t 	filelen= 	lseek(fdin, 0, SEEK_END);
	int 	totalread=	0;	// Measures total bytes, only plaintext


	// Reset infile position
	lseek(fdin, 0, SEEK_SET);

	// Generate key using PBKDF2
	error= gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, strlen(salt), 4096, KEYLEN, key);
	if (error) {
		printf("[ERROR] Problems occurred during keygen: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(6);
	}

	// Set the handle, key, and initialization vector
	error= gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
	if (error) {
		printf("[ERROR] Problems occurred during handle setup: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(7);
	}

	error= gcry_cipher_setkey(handle, key, KEYLEN);
	if (error) {
		printf("[ERROR] Problems occurred while setting the key: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(8);
	}

	error= gcry_cipher_setiv(handle, iv, BLKLEN);
	if (error) {
		printf("[ERROR] Problems occurred while setting the IV: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(9);
	}
	

	// Send filename length and string first, if sending to daemon
	if (sockfd != -1) {
		uint32_t fnamelen= strlen(filename);

		int res1= send(sockfd, &fnamelen, sizeof(uint32_t), 0);
		int res2= send(sockfd, filename, fnamelen, 0);
		if (res1 == -1 || res2 == -1) {
			perror("Error in sending file info");
		}
	}


	// Begin looping and encrypting
	while (totalread < filelen) {
		memset(inbuf, 0, MAX_CHUNK + HMAC_SIZE);
		memset(outbuf, 0, MAX_CHUNK + HMAC_SIZE);
		
		bytesread= read(fdin, inbuf, MAX_CHUNK);
		if (bytesread == -1) {
			printf("[ERROR] Problems occurred while reading the input file\n"); 
			exit(10);
		}

		// Handle end-transmission padding, following RFC 5652
		// See http://tools.ietf.org/html/rfc5652#section-6.3
		if (bytesread != MAX_CHUNK) {
			int total= (BLKLEN * (bytesread / BLKLEN + 1));
			int padamt= total - bytesread;
			bytesread= total;
			int i;
			for (i= padamt; i > 0; i--) {
				inbuf[bytesread - i]= (char) padamt;
			}
		}

		// Generate HMAC hash and encrypt
		genMAC(inbuf, bytesread, &inbuf[bytesread], HMAC_SIZE, key, KEYLEN);
		error= gcry_cipher_encrypt(handle, outbuf, MAX_CHUNK + HMAC_SIZE, inbuf, bytesread + HMAC_SIZE);
		if (error) {
			printf("[ERROR] Problems occurred while encrypting plaintext: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
			exit(11);
		}
		totalread += bytesread;
		
		// Send to applicable outputs
		if (localfd != -1) {
			byteswrote=	write(localfd, outbuf, bytesread + HMAC_SIZE);
		}

		if (sockfd != -1) {
			byteswrote=	send(sockfd, outbuf, bytesread + HMAC_SIZE, 0);
		}
		
		bytestotal += byteswrote;
		printf("read %d bytes, wrote bytes %d\n", bytesread, byteswrote);
		
	} // End encrypytion while-loop

	printf("Successfully encrypted %s to %s.uo(%d bytes written).\n", filename, filename, bytestotal);
	if (sockfd != -1) {
	
	}

	// Cleanup gcrypt vars and alloc'd memory
	gcry_cipher_close(handle);
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
		exit(2);
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
		printf("[ERROR] Problems occurred while opening the HMAC handle: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(12);
	}

	error= gcry_md_setkey(handle, key, klen);
	if (error) {
		printf("[ERROR] Problems occurred while setting the HMAC key: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(13);
	}

	// Add buffer contents and finalize hash
	gcry_md_write(handle, inbuf, ilen);

	error= gcry_md_final(handle);
	if (error) {
		printf("[ERROR] Problems occurred while generating the HMAC: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		exit(14);
	}

	// Point to the finalized hash and test it
	unsigned char *digest= gcry_md_read(handle, GCRY_MD_SHA256);
	if (digest == NULL) {
		printf("[ERROR] Problems occurred in reading the HMAC\n");
		exit(15);
	}

	if (dest == NULL) {
		return (char*) digest;
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


/* ---------------------------------------------------------------- //i
	void printUsage - Displays command-line format and options
		for running uoenc
// ---------------------------------------------------------------- */
void printUsage() {
	printf("%s\n", "Usage: uoenc <input file> [-d <output IP-addr:port>] [-l]");
}


/* ---------------------------------------------------------------- //
	int setupLocal - Verifies and opens the local cipher output file

	char*	infile	: The plaintext filename, used to generate the
						ciphertext filename
	
	returns	: the file descriptor on success
			: -1 if the file already exists, or on failure
// ---------------------------------------------------------------- */
int setupLocal(char *infile) {
	char *outname= (char*) malloc(sizeof(char) * (strlen(infile) + 3));
	sprintf(outname, "%s.uo", infile);

	int res= access(outname, F_OK);
	if (res != -1) { return -1; }

	int fd= open(outname, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	free(outname);

	return fd;
}


/* ---------------------------------------------------------------- //
	int setupSocket - Connects a TCP socket to the decrypt daemon
	
	char*	addr	: The hostname or IP address to connect to
	char*	port	: The port to connect on

	returns	: The file descriptor on success
			: -1 on failure

	NOTE: Most of this method has been appropriated from Beej's
		Guide to Network Programming.
		See http://beej.us/guide/bgnet for mor details.
// ---------------------------------------------------------------- */
int setupSocket(char *addr, char *port) {
	int result= 0;
	int sockfd= -1;

	// Setup hints
	struct addrinfo hints;
	struct addrinfo *servinfo, *p;
	memset(&hints, 0, sizeof(struct addrinfo));
	hints.ai_family= AF_INET;
	hints.ai_socktype= SOCK_STREAM;

	// Fetch address info struct
	if ((result= getaddrinfo(addr, port, &hints, &servinfo)) != 0) {
		fprintf(stderr, "getaddrinfo: %s\n", gai_strerror(result));
		return -1;
	}

	// Create TCP socket
	for (p= servinfo; p != NULL; p= p->ai_next) {
		sockfd= socket(p->ai_family, p->ai_socktype, p->ai_protocol);
		if (sockfd == -1) {
			perror("socket: ");
			continue;
		}

		if (connect(sockfd, p->ai_addr, p->ai_addrlen) == -1) {
			close(sockfd);
			sockfd= -1;
			perror("client: connect");
			continue;
		}
		break;
	}

	return sockfd;
}


/* ---------------------------------------------------------------- //
	void test_printKey - A testing method to print the given key
		in hex representation for comparison
	
	char*	key : The keybuffer to print in hex format
// ---------------------------------------------------------------- */
void test_printKey(char *key) {
	const size_t KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);

	printf("key:\t");
	int j;
	for (j= 0; j < KEYLEN; j++) {
		printf("%02x", (char)key[j]);
	}
	printf("\n");
}
