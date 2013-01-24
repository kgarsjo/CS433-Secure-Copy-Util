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
void encrypt();
void gcryptInit();
void printUsage();
void save();
void transmit();

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

	gcry_cipher_hd_t handle;
	gcry_error_t	 error;


	gcryptInit();

	// Argument validity checks
	if (argc >= 2) {
		inputFile= argv[1];

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

	if (!validArgs) {
		printUsage();
		return 1;
	}

	// Prompt for password and encrypt
	printf("Password: ");
	size_t size= blocksize;
	int res= getline(&password, &size, stdin);
	if (res == -1) {
		printf("\nERROR\n");
	}

	encrypt(inputFile);
	if (localFlag) {
		save();
	}
	if (dumpFlag) {
		transmit();
	}
	
	return 0;
}


void encrypt() { };


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


void save() { }


void transmit() { }
