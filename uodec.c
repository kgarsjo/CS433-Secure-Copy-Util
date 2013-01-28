#include <fcntl.h>
#include <errno.h>
#include <gcrypt.h>
#include <stdio.h>
#include <string.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <unistd.h>

const int MAX_CHUNK= 1024;

int main(int argc, char **argv) {
	
	if (argc != 2) { exit(1); }
	char *filename= argv[1];

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

		// Disregard HMAC for now.
		numread -= 16;
		
		// Handle padding at end
		int padamt= 0;
		if (numread % MAX_CHUNK != 0) {
			padamt= outbuf[numread - 1];
		}
		
		numwrote= write(fdout, outbuf, numread - padamt);
		numtotal += numwrote;
	}
	if (numread == 0) {
		printf("\n\nSuccessfully encrypted (%d bytes written)\n", numtotal);
	}

	close(fdin);
	close(fdout);

	return 0;
}
