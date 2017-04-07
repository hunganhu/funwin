SRCS=ftdparse.cpp my_pcap.cpp

EXECUTABLES=ftdparse

CC=g++
CPPFLAGS=-g -Wall

LDFLAGS=-g -lpcap -L../lib -lCFFEXtraderapi -lssl -lcrypto

OBJS=$(SRCS:.cpp=.o)

all: $(EXECUTABLES)

$(EXECUTABLES): $(OBJS)
	$(CC) $(CPPFLAGS) $(OBJS) $(LDFLAGS) -o $@  

.cpp.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

clean:
	rm -rf $(EXECUTABLES) $(OBJS) *~
