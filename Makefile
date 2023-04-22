CC = g++

CFLAGS = -std=c++17 -g -Wall

TARGET = flow

all: flow

flow: flow.cpp
	$(CC) $(CFLAGS) -o flow flow.cpp -lpcap

clean:
	rm flow