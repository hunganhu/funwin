SRCS=ftdparse.c my_pcap.c

EXECUTABLES=ftdparse

CC=gcc
CFLAGS=-g -Wall

LDFLAGS=-lpcap

OBJS=$(SRCS:.c=.o)

all: $(EXECUTABLES)

$(EXECUTABLES): $(OBJS)
	$(CC) $(CFLAGS) $(OBJS) $(LDFLAGS) -o $@  

.c.o: my_pcap.h
	$(CC) $(CFLAGS) -c $< -o $@

clean:
	rm -rf $(EXECUTABLES) $(OBJS) *~
