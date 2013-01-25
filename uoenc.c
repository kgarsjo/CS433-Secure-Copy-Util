#include <errno.h>
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>

/* -------------------------------- //
	Golbal Variables
// -------------------------------- */
const char* const dFlagStr= "-d";
const char* const lFlagStr= "-l";
const size_t blocksize= 1024;


/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void encrypt(char*, char*);
void gcryptInit();
void printUsage();
void save(char*);
void transmit(char*, char*);
void testAES();

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {
	char *inputFile		= (char*) malloc(sizeof(char) * blocksize);
	char *outputIP		= (char*) malloc(sizeof(char) * blocksize);
	char *outputPort	= (char*) malloc(sizeof(char) * blocksize);
	char *password		= NULL;	

	int dumpFlag		= 0;
	int localFlag		= 0;
	int validArgs		= 0;



	gcryptInit();

	// Argument validity checks
	if (argc >= 2) {
		strcpy(inputFile, argv[1]); //TODO Error checking
		validArgs= 1;
		
		if (argc > 2) {
			int i;
			for (i= 2; i < argc; i++) {
				int resd= strcmp(dFlagStr, argv[i]);
				int resl= strcmp(lFlagStr, argv[i]);

				// Dump flag detection
				if (resd == 0) {
					if (dumpFlag) { validArgs= 0; break; }
					dumpFlag= 1;

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

	// Prompt for password and encrypt
	printf("Password: ");
	size_t size= blocksize;
	int res= getline(&password, &size, stdin);
	if (res == -1) {
		perror("getline:");
		exit(3);
	}

	encrypt(inputFile, password);
	/*if (localFlag) {
		save(NULL);
	}
	if (dumpFlag) {
		transmit(NULL, NULL);
	}
	*/

	//testAES();

	return 0;
}


void encrypt(char *filename, char *password) { 
	gcry_cipher_hd_t handle;
	gcry_error_t	 error;

	const size_t KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	const size_t BLKLEN= gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	const char *salt= "saltyEnough?";


	// Generate key using PBKDF2
	char *key= (char*) malloc(sizeof(char) * KEYLEN);
	error= gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 12, 4096, KEYLEN, key);
	if (error) {
		printf("Problem with keygen...");
	}
	printf("key:\t");
	int j;
	for (j= 0; j < KEYLEN; j++) {
		printf("%02x", (unsigned char)key[j]);
	}
	printf("\n");


	// Set the handle and key
	error= gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_ECB, 0);
	if (error) {
		printf("Problem with algo open...");
	}

	error= gcry_cipher_setkey(handle, key, KEYLEN);
	if (error) {
		printf("Problem with setkey...");
	}


	// Buffer the plaintext, pad if necessary
	FILE *fptr= fopen(filename, "r");
	if (fptr == NULL) {
		perror("Error opening plaintext: ");
	}

	int res= fseek(fptr, 0, SEEK_END);
	if (res == -1) {
		perror("Error reading file length: ");
	}

	size_t fsize= ftell(fptr) + 1;
	res= fseek(fptr, 0, SEEK_SET);

	size_t netsize= fsize;
	if (fsize % BLKLEN != 0) {
		netsize= (fsize / BLKLEN + 1) * BLKLEN;
	}

	char *plaintext= (char*) malloc(sizeof(char) * netsize);
	memset(plaintext, 0, netsize);
	fread(plaintext, fsize, 1, fptr);
	plaintext[fsize]= '\0';
	//TODO Error handling

	fclose(fptr);

	char *encbuf= (char*) malloc(sizeof(char) * netsize * 2);
	memset(encbuf, 0, netsize * 2);
	
	
	// Encrypt the plaintext
	error= gcry_cipher_encrypt(handle, encbuf, netsize * 2, plaintext, netsize);
	if (error) {
		printf("Error encrypting plaintext");
	}

	printf("Plaintext:\t%s\n", plaintext);
	printf("Ciphertext\t");
	for(j= 0; j < netsize * 2; j++) {
		printf("%02x", (unsigned char) encbuf[j]);
	}
	printf("\n");
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


void save(char* filename) { 

}


void transmit(char* ipaddr, char* port) { 

}


void testAES() {
	size_t KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	size_t BLKLEN= gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);

	char 	*plaintext= 	malloc(BLKLEN * 4);
	size_t 	ptextSize= 	BLKLEN * 4;
	char 	*encbuf= 	malloc(BLKLEN * 10);
	char	*outbuf=	malloc(ptextSize);
	char 	*key= 		"one test aes key                ";
	char 	*iv= 		"inivec";

	gcry_error_t		error;
	gcry_cipher_hd_t 	handle;

	memset(plaintext, 0, BLKLEN * 4);
	strcpy(plaintext, "a man a plan a canal panama");
	printf("PLAINTEXT:\t%s\n", plaintext);

	error= gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, 0);
	if (error) {
		printf("Error in open: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		return;
	}

	error= gcry_cipher_setkey(handle, key, KEYLEN);
	if (error) {
		printf("Error in setkey: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		return;
	}

	/*error= gcry_cipher_setiv(handle, iv, BLKLEN);
	if (error) {
		printf("Error in setiv: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		return;
	}*/

	error= gcry_cipher_encrypt(handle, plaintext, BLKLEN * 4, NULL, 0);
	if (error) {
		printf("Error in encrypt: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		return;
	}

	printf("CIPHERTEXT:\t");
	int i;
	for (i= 0; i < ptextSize; i++) {
		printf("%02X", (unsigned char) plaintext[i]);
	}
	printf("\n");

	/*error= gcry_cipher_setiv(handle, iv, BLKLEN);
	if (error) {
		printf("Error in setiv: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		return;
	}*/

	error= gcry_cipher_decrypt(handle, plaintext, BLKLEN * 4, NULL, 0);
	if (error) {
		printf("Error in decrypt: %s | %s\n", gcry_strsource(error), gcry_strerror(error));
		return;
	}	

	printf("OUTPUTTEXT:\t%s\n", plaintext);

}
