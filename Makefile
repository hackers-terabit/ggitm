CC=gcc
CFLAGS=  -g -lseccomp -lcurl
LDFLAGS=
SOURCES=main.c util.c network.c dnsmap.c ggitm.c

EXECUTABLE=ggitm

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)