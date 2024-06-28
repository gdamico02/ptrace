CC = gcc
TARGET = ptrace
FLAGS = -Wall -ansi -pedantic

all: $(TARGET) clean

clean:
	-rm main.o source.o

$(TARGET): main.o source.o
	$(CC) -lm main.o source.o -o $(TARGET) $(FLAGS)

source.o: source.c
	$(CC) -c source.c

main.o: main.c
	$(CC) -c main.c

