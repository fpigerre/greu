CC = gcc
PROGRAM = greu
SOURCES = $(wildcard *.c)
OBJECTS = $(patsubst %.c, %.o, $(SOURCES))
MAN =
LINKER_LIBS = -levent
CFLAGS += -Wall -Werror -g
DEBUG = -g

build: $(OBJECTS)
	gcc $(DEBUG) $(LINKER_LIBS) $(OBJECTS) -o $(PROGRAM)
	
.c.o: $(SOURCES)
	gcc $(DEBUG) -c $< -o $@
	
.PHONY: clean
clean:
	rm -rf $(PROGRAM) *.o
