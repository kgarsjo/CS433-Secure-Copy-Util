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
		strcpy(argv[1], inputFile); //TODO Error checking
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
	if (localFlag) {
		save(NULL);
	}
	if (dumpFlag) {
		transmit(NULL, NULL);
	}
	
	return 0;
}


void encrypt(char *filename, char *key) { 
	gcry_cipher_hd_t handle;
	gcry_error_t	 error;
	
	// Set the handle and key for AES256 algo
	error= gcry_cipher_open(&handle, GCRY_CIPHER_AES256, GCRY_CIPHER_MODE_CBC, GCRY_CIPHER_SECURE);
	if (error) {
		printf("Error in opening handler!\n");
	}

	error= gcry_cipher_setkey(handle, key, sizeof(key));
	if (error) {
		printf("Error in keyset!\n");
	}


	// Buffer the plaintext
	FILE *fptr= fopen(filename, "r");
	if (fptr == NULL) {
		perror("Error opening plaintext: ");
	}

	int res= fseek(fptr, 0, SEEK_END);
	if (res == -1) {
		perror("Error reading file length: ");
	}

	size_t fsize= ftell(fptr);
	res= fseek(fptr, 0, SEEK_SET);

	char *plaintext= (char*) malloc(sizeof(char) * fsize);
	size_t numread= fread(plaintext, fsize, 1, fptr);
	//TODO Error handling

	fclose(fptr);


	// Encrypt the buffer
	char *ciphertext= (char*) malloc(sizeof(char) * fsize * 100);	
	error= gcry_cipher_encrypt(handle, ciphertext, sizeof(ciphertext), plaintext, sizeof(plaintext));
	if (error) {
		printf("Error encrypting the plaintext!\n");
	}


	// Output the ciphertext
	// TODO Change method return to a ptr to ciphertext block and handle ciphertext elsewhere
	char *ciphername= (char*) malloc(sizeof(filename) + 3);
	strcpy(ciphername, filename);
	strcat(ciphername, ".uo"); //TODO make extension global constant
	
	FILE* cptr= fopen(ciphername, "W+");
	if (cptr == NULL) {
		perror("Error creating ciphertext file: ");
	}

	fwrite(ciphertext, sizeof(ciphertext), 1, cptr);
	fclose(cptr); 
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
