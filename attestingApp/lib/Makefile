all:
	gcc -c -Wall -Werror -fpic encrypt.c
	gcc -shared -o libencrypt.so encrypt.o
	cp libencrypt.so /usr/lib64/
