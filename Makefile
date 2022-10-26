all: inject sample

inject: inject.c
	gcc inject.c -Wall -Wextra -o inject -std=c99

sample: sample-process/sample.c
	gcc sample-process/sample.c -o sample-process/sample -std=c99

clean: 
	rm -f inject sample-process/sample
