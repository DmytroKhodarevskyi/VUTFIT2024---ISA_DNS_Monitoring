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
SOURCES = $(wildcard *.cpp)
OBJECTS = $(SOURCES:.cpp=.o)

# Default target: Build the project with debugging symbols
all: $(TARGET)

# Link the target with all object files
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile each source file to an object
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up the build
clean:
	rm -f $(TARGET) $(OBJECTS)

# Phony targets for commands that do not represent files
.PHONY: clean all

# Run the program with gdb for debugging
debug: $(TARGET)
	gdb $(TARGET)
