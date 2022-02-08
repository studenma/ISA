CC=gcc
CFLAGS=-std=c99 -Wall -Wextra -pedantic -lpcap -D_BSD_SOURCE
PROJ2=myripresponse

all: $(PROJ2).c
	$(CC) $(CFLAGS) $(PROJ2).c -o $(PROJ2)    

clean:
	rm $(PROJ1)
