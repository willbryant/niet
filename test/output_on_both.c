#include <unistd.h>
#include <stdio.h>

int main(int argc, char* argv[]) {
	fprintf(stdout, "%s", "some output on stdout\n");
	fprintf(stderr, "%s", "some output on stderr\n");
	return 0;
}
