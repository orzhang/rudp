CC=gcc
CFLAGS=-c -g
INC=-I . -I .. -I ../../opensource/include
LDFLAGS=-L ../../opensource/libs/x86_64 -l event 

SRCFILES=../ikcp.c	\
		 ../rudp_socket_utils.c	\
		 ../rudp_client.c	\
		 ../rudp_server.c	\
		 ../rudp_connect.c	\
		 ../rudp_stream.c	\
		 ../fec.c	\
		 ../rs.c	\

OBJFILES=$(SRCFILES:.c=.o)

all: rudp_client_test rudp_server_test

rudp_client_test: $(OBJFILES) rudp_client_test.o
	$(CC) $(OBJFILES) $@.o -o $@ $(LDFLAGS)

rudp_server_test: $(OBJFILES) rudp_server_test.o
	$(CC) $(OBJFILES) $@.o -o $@ $(LDFLAGS)

.c.o:
	$(CC) $(CFLAGS) $(INC) $< -o $@

print-%:
	@echo $* = $($*)

clean:
	rm *.o ../*.o rudp_client_test rudp_server_test
