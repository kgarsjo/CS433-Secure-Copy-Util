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
const int MAX_CHUNK= 1024;

/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void decrypt(char*, int, int);
char*	genMAC(char*, int, char*, int, char*, int);

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {
	
	if (argc != 2) { exit(1); }
	char *filename= argv[1];


	// Open the input and output files
	int fdin= open(filename, O_RDONLY);
	if (fdin == -1) {
		perror("Opening encrypted file");
	}

	int fdout= open("decrypt.test", O_RDWR | O_CREAT, S_IRUSR | S_IWUSR);
	if (fdout == -1) {
		perror("Opening output file");
	}


	// Prompt for password
	char *password= NULL;
	printf("Password: ");
	size_t size= MAX_CHUNK;
	int res= getline(&password, &size, stdin);
	if (res == -1) {
		perror("getline:");
		exit(3);
	}

	decrypt(password, fdin, fdout);

	close(fdin);
	close(fdout);
	free(password);

	return 0;
}

void decrypt(char *password, int fdin, int fdout) {
	gcry_cipher_hd_t handle;
	gcry_error_t	 error;

	const size_t KEYLEN= gcry_cipher_get_algo_keylen(GCRY_CIPHER_AES256);
	const size_t BLKLEN= gcry_cipher_get_algo_blklen(GCRY_CIPHER_AES256);
	const char *salt= "saltyEnough?";
	const char *iv=   "inivec\0\0\0\0\0\0\0\0\0\0";


	// Generate key using PBKDF2
	char *key= (char*) malloc(sizeof(char) * KEYLEN);
	error= gcry_kdf_derive(password, strlen(password), GCRY_KDF_PBKDF2, GCRY_MD_SHA256, salt, 12, 4096, KEYLEN, key);
	if (error) {
		printf("Problem with keygen...");
	}

	// Set the handle and key
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

	char *inbuf= (char*) malloc(sizeof(char) * MAX_CHUNK + 16);
	char *outbuf= (char*) malloc(sizeof(char) * MAX_CHUNK + 16);

	// Begin looping and encrypting
	// TODO clean up loop condition
	int numread= 0;
	int numwrote= 0;
	int numtotal= 0;

	while (1) {
		memset(inbuf, 0, MAX_CHUNK + 16);
		memset(outbuf, 0, MAX_CHUNK);
		
		numread= read(fdin, inbuf, MAX_CHUNK + 16);
		if (numread == -1 || numread == 0) {
			break;
		}


		// Decrypt and check HMAC
		error= gcry_cipher_decrypt(handle, outbuf, numread, inbuf, numread);
		if (error) {
			printf("Error decrypting plaintext\n");
		}

		int msglen= numread - 16;
		char *HMAC= &outbuf[msglen];
		char *digest= genMAC(outbuf, msglen, NULL, 0, key, KEYLEN);
		int res= strncmp(HMAC, digest, 16);
		if (res != 0) {
			printf("[ERROR] MAC digests do not match!\n");
		}

		// Handle padding at end
		int padamt= 0;
		if (msglen % MAX_CHUNK != 0) {
			padamt= outbuf[msglen - 1];
		}
		
		numwrote= write(fdout, outbuf, msglen - padamt);
		numtotal += numwrote;
		printf("read %d bytes, wrote bytes %d\n", numread, msglen);
	}
	if (numread == 0) {
		printf("\nSuccessfully encrypted (%d bytes written)\n", numtotal);
	}

	free(inbuf);
	free(outbuf);
}


char* genMAC(char *inbuf, int ilen, char *dest, int destlen, char *key, int klen) {
	gcry_md_hd_t handle;
	gcry_error_t error;
	int digestlen= gcry_md_get_algo_dlen(GCRY_MD_SHA256);

	// Set the HMAC handle and key
	error= gcry_md_open(&handle, GCRY_MD_SHA256, GCRY_MD_FLAG_HMAC);
	if (error) {
		printf("Error opening HMAC MD handle\n");
	}

	error= gcry_md_setkey(handle, key, klen);
	if (error) {
		printf("Error setting HMAC key\n");
	}

	// Add buffer contents and finalize hash
	gcry_md_write(handle, inbuf, ilen);

	error= gcry_md_final(handle);
	if (error) {
		printf("Error generating HMAC\n");
	}

	unsigned char *digest= gcry_md_read(handle, GCRY_MD_SHA256);
	if (digest == NULL) {
		printf("Error in reading HMAC\n");
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
