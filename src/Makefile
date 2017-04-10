SRCS=ftdparse.cpp my_pcap.cpp

EXECUTABLES=ftdparse

CC=g++
CPPFLAGS=-g -Wall

LDFLAGS=-g -lpcap -L../lib -lCFFEXtraderapi -lssl -lcrypto -lz

OBJS=$(SRCS:.cpp=.o)

all: $(EXECUTABLES)

$(EXECUTABLES): $(OBJS)
	$(CC) $(CPPFLAGS) $(OBJS) $(LDFLAGS) -o $@  

.cpp.o:
	$(CC) $(CPPFLAGS) -c $< -o $@

zip:
	zip -r hunganhu.hu_hunganhu@yahoo.com_2017.04.10.zip .

clean:
	rm -rf $(EXECUTABLES) $(OBJS) *~
