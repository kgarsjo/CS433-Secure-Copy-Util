#include <stdio.h>

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
		if (argc == 3) {
			
		} else if (argc == 4) {

		} else if (argc == 5) {

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
