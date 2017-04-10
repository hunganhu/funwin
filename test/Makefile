SRCS=lzwtest.cpp gztest.c

EXECUTABLES=lzwtest gztest

CC=g++
CPPFLAGS=-g -Wall

LDFLAGS=-lpcap -lssl -lcrypto -lz

OBJS=lzwtest.o gztest.o

all: lzwtest gztest

lzwtest: lzwtest.cpp
	g++ $(CPPFLAGS) lzwtest.cpp $(LDFLAGS) -o $@
gztest: gztest.c
	gcc $(CPPFLAGS) gztest.c $(LDFLAGS) -o $@  

clean:
	rm -rf $(EXECUTABLES) $(OBJS) *~
