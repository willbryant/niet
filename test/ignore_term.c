#include <stdio.h>
#include <signal.h>

void term(int signo) {
	fprintf(stdout, "ignoring TERM signal\n");
}

int main(int argc, char* argv[]) {
	signal(SIGTERM, &term);
	while(1) pause();
	return 0;
}
