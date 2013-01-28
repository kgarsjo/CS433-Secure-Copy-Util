#include <fcntl.h>
#include <errno.h>
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

/* -------------------------------- //
	Golbal Variables
// -------------------------------- */
const char* const 	dFlagStr= "-d";
const char* const 	lFlagStr= "-l";
const int 		MAX_CHUNK= 1024;


/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void 	encryptAndSend(char*, char*, int, int, int);
void 	gcryptInit();
char*	getMAC(char*, int);
void 	printUsage();
int	setupLocal(char*);
void 	setupSocket(char*, char*);
void 	test_printKey(char*);

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {
	char *inputFile		= NULL;
	char *outputIP		= (char*) malloc(sizeof(char) * 16);
	char *outputPort	= (char*) malloc(sizeof(char) * 5);
	char *password		= NULL;	

	int daemonFlag		= 0;
	int localFlag		= 1;	// Defaults to Local Operation
	int validArgs		= 0;

	int localfd		= -1;
	int sockfd		= -1;

	gcryptInit();

	// Argument validity checks
	if (argc >= 2) {
		inputFile= argv[1];
		validArgs= 1;
		
		if (argc > 2) {
			int i;
			for (i= 2; i < argc; i++) {
				int resd= strcmp(dFlagStr, argv[i]);
				int resl= strcmp(lFlagStr, argv[i]);

				// Dump flag detection
				if (resd == 0) {
					if (daemonFlag) { validArgs= 0; break; }
					daemonFlag= 1;

					i++;
					if (i >= argc) { validArgs= 0; break; }
					outputIP= argv[i];

					validArgs= 1;

				// Local flag detection
				} else if (resl == 0) {
					if (localFlag) { validArgs= 0 ; break; }
					localFlag= 1;
					validArgs= 1;

				// Catch-all for everything else
				} else { validArgs= 0; break; }
			}
		}
	}
	if (!validArgs) {
		printUsage();
		return 1;
	}

	// Open the input file
	int fdin= open(inputFile, O_RDONLY);
	if (fdin == -1) {
		printf("[ERROR] Could not open file %s\n", inputFile);
		exit(3);
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
			exit(3);
		}
	}
	if (daemonFlag) {
		setupSocket(NULL, NULL);
	}
	encryptAndSend(inputFile, password, fdin, sockfd, localfd);
	

	// Cleanup File Descriptors and alloc'd memory
	close(fdin);
	close(localfd);
	close(sockfd);

	free(outputIP);
	free(outputPort);

	return 0;
}


void encryptAndSend(char *filename, char *password, int fdin, int sockfd, int localfd) { 

	gcry_cipher_hd_t handle;
	gcry_error_t	 error;
	const size_t 	KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	const size_t 	BLKLEN= gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	
	const char *salt= "saltyEnough?";
	const char *iv=   "inivec\0\0\0\0\0\0\0\0\0\0";
	const char *hmac= "\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0\0";

	char *inbuf=  	(char*) malloc(sizeof(char) * MAX_CHUNK);
	char *outbuf= 	(char*) malloc(sizeof(char) * MAX_CHUNK + 16);

	int 	bytesread= 	0;
	int 	byteswrote= 	0;
	int	bytestotal= 	0;
	off_t 	filelen=	lseek(fdin, 0, SEEK_END);

	// Reset infile position
	lseek(fdin, 0, SEEK_SET);

	// Generate key using PBKDF2
	char *key= (char*) malloc(sizeof(char) * KEYLEN);
	error= gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 12, 4096, KEYLEN, key);
	if (error) {
		printf("Problem with keygen...");
	}
	test_printKey(key);


	// Set the handle, key, and initialization vector
	error= gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
	if (error) {
		printf("Problem with algo open...");
	}

	error= gcry_cipher_setkey(handle, key, KEYLEN);
	if (error) {
		printf("Problem with setkey...");
	}

	error= gcry_cipher_setiv(handle, iv, BLKLEN);
	if (error) {
		printf("Problem with setiv...");
	}


	// Begin looping and encrypting
	while (bytesread < filelen) {
		memset(inbuf, 0, MAX_CHUNK);
		memset(outbuf, 0, MAX_CHUNK + 16);
		
		bytesread= read(fdin, inbuf, MAX_CHUNK);
		if (bytesread == -1) {
			printf("[ERROR] Problems occurred in reading the input file\n"); 
			exit(3);
		}

		// Handle end-transmission padding
		if (bytesread != MAX_CHUNK) {
			int total= (BLKLEN * (bytesread / BLKLEN + 1));
			char padamt= total - bytesread;
			bytesread= total;

			int i;
			for (i= padamt; i > 0; i--) {
				inbuf[bytesread - i]= padamt;
			}
		}

		error= gcry_cipher_encrypt(handle, outbuf, MAX_CHUNK, inbuf, bytesread);
		if (error) {
			printf("Error encrypting plaintext\n");
		}
		
		// Send to applicable outputs
		if (localfd != -1) {
			byteswrote=   write(localfd, outbuf, bytesread);
			byteswrote += write(localfd, hmac, 16);
		}
		
		bytestotal += byteswrote;
		printf("read %d bytes, wrote bytes %d\n", bytesread, byteswrote);
		
	}

	printf("Successfully encrypted %s to %s.uo(%d bytes written).\n", filename, filename, bytestotal);

	// Cleanup gcrypt vars and alloc'd memory
	gcry_cipher_close(handle);
	free(inbuf);
	free(outbuf);
}


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


void printUsage() {
	printf("%s\n", "Usage: uoenc <input file> [-d <output IP-addr:port>] [-l]");
}


int setupLocal(char *infile) {
	char *outname= (char*) malloc(sizeof(char) * (strlen(infile) + 3));
	sprintf(outname, "%s.uo", infile);
	int res= access(outname, F_OK);
	if (res != -1) { return -1; }

	int fd= open(outname, O_CREAT | O_RDWR, S_IRUSR | S_IWUSR);
	free(outname);

	return fd;
}


void setupSocket(char *ip, char *port) {

}


void test_printKey(char *key) {
	const size_t KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);

	printf("key:\t");
	int j;
	for (j= 0; j < KEYLEN; j++) {
		printf("%02x", (unsigned char)key[j]);
	}
	printf("\n");
}
