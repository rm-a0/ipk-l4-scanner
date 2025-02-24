CC = g++
CFLAGS = -std=c++20 -Wall -Wextra -pedantic
SRC = src/main.cpp
TARGET = ipk-l4-scan

all:
	$(CC) $(CFLAGS) $(SRC) -o $(TARGET)