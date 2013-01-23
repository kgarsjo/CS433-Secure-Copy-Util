/* -------------------------------- //
	Function Prototypes
// -------------------------------- */
void printUsage();

/* -------------------------------- //
	Program Entry
// -------------------------------- */
int main(int argc, char **argv) {
	if (argc == 1) {

	} else if (argc == 2) {

	} else if (argc == 4) {

	} else {
		printUsage();
		return 1;
	}
	
	printf("%s", "All is well!");
	return 0;
}
