all: myELF

myELF: myELF.o 
	gcc -m32 -g -Wall -o myELF myELF.o 

myELF.o: myELF.c
	gcc -g -Wall -m32 -c -o myELF.o myELF.c

.PHONY: clean

clean: 
	rm -f *.o myELF
