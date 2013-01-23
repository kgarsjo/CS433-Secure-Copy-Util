#include <stdio.h>
#include <string.h>

/* -------------------------------- //
	Golbal Variables
// -------------------------------- */
const char* const dFlagStr= "-d";
const char* const lFlagStr= "-l";

/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void printUsage();

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {
	char *inputFile		= NULL;
	char *outputIP		= NULL;
	char *outputPort	= NULL;
	
	int dumpFlag		= 0;
	int localFlag		= 0;
	int validArgs		= 0;

	// Argument validity checks
	if (argc >= 2) {
		inputFile= argv[1];
		int i;
		for (i= 1; i < argc; i++) {
			int resd= strcmp(dFlagStr, argv[i]);
			int resl= strcmp(lFlagStr, argv[i]);

			if (resd == 0) {
				if (dumpFlag) { validArgs= 0; break; }
				dumpFlag= 1;
				
				i++;
				if (i >= argc) { validArgs= 0; break; }
				outputIP= argv[i];
				
				validArgs= 1;
			} else if (resl == 0) {
				if (localFlag) { validArgs= 0 ; break; }
				localFlag= 1;
				validArgs= 1;
			} else { validArgs= 0; break; }
		}
	}

	if (!validArgs) {
		printUsage();
		return 1;
	}
	
	printf("%s\n", "All is well!");
	return 0;
}


void printUsage() {
	printf("%s\n", "Usage: uoenc <input file> [-d <output IP-addr:port>] [-l]");
}
