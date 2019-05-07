all: inject sample

inject: inject.c
	gcc inject.c -Wall -Wextra -o inject

sample: sample-process/sample.c
	gcc sample-process/sample.c -o sample-process/sample

clean: 
	rm -f inject sample-process/sample