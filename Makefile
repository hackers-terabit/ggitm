CC=gcc
CFLAGS=  -g -lseccomp -lcurl -lxml2 -lpcre -pthread
LDFLAGS=
SOURCES=main.c util.c network.c  ruleparser.c pcrs/pcrs.c siphash24.c ggitm.c 

EXECUTABLE=ggitm

all: $(SOURCES) 
		$(CC) $(CFLAGS) -o $(EXECUTABLE) $(SOURCES)