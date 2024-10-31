#include <stdlib.h>

int main() {
	pid_t pid = getpid();
	sleep(1);
	fork();
	exit(0);
}
