CC=gcc
CFLAGS=  -g -lseccomp -lcurl -lxml2 -lpcre
LDFLAGS=
SOURCES=main.c util.c network.c dnsmap.c ruleparser.c pcrs/pcrs.c ggitm.c 

EXECUTABLE=ggitm

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)