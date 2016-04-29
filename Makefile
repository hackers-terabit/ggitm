CC=gcc
CFLAGS=  -g -lseccomp
LDFLAGS=
SOURCES=main.c util.c network.c dnsmap.c ggitm.c

EXECUTABLE=ggitm

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)