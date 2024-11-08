# @file: makefile
# @author: Dmytro Khodarevskyi
# @login: xkhoda01
# @brief: makefile for compiling code

# Compiler settings
CXX = g++
CXXFLAGS = -g -Wall -Wextra -std=c++20 -fno-omit-frame-pointer
# CXXFLAGS = -g -Wall -Wextra -std=c++20 -fno-omit-frame-pointer -fsanitize=address

# Linker flags
LDFLAGS = -lpcap
# LDFLAGS = -lpcap -fsanitize=address

# Build settings
TARGET = dns-monitor
# SOURCES = $(wildcard *.cpp)
# OBJECTS = $(SOURCES:%.cpp=%.o)

# Default target: Build the project with debugging symbols
all: $(TARGET)

main.o : main.cpp
	$(CXX) $(CXXFLAGS) -c main.cpp -o main.o

Monitor.o : Monitor.cpp Monitor.hpp
	$(CXX) $(CXXFLAGS) -c Monitor.cpp -o Monitor.o

ParseArgs.o : ParseArgs.cpp ParseArgs.hpp
	$(CXX) $(CXXFLAGS) -c ParseArgs.cpp -o ParseArgs.o

$(TARGET): Monitor.o ParseArgs.o main.o
	$(CXX) $(CXXFLAGS) main.o Monitor.o ParseArgs.o -o $(TARGET) $(LDFLAGS)

# Clean up the build
clean:
	rm -f $(TARGET) *.o

# Phony targets for commands that do not represent files
.PHONY: clean all

# Run the program with gdb for debugging
debug: $(TARGET)
	gdb $(TARGET)
