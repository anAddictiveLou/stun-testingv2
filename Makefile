.PHONY: all clean

all: 
	gcc -o stun_client main.c stun.c nat_traversal.c nat_type.c -I. -g -lpthread
clean: 
	rm stun_client