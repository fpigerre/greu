CC = gcc
PROGRAM = greu
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c, %.o, $(SOURCES))
MAN =
LINKER_LIBS = -levent
CFLAGS += -Wall -Werror -g
DEBUG = -g

all: $(OBJECTS)
	gcc $(LINKER_LIBS) log.o greu.o -o $(PROGRAM)
	
.c.o: $(SOURCES)
	gcc -c $< -o $@
	
.PHONY: clean
clean:
	rm -rf $(PROGRAM) *.o