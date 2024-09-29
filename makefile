# Compiler settings
CXX=g++
CXXFLAGS=-g -Wall -Wextra -std=c++20

# Linker flags
LDFLAGS=-lpcap

# Build settings
TARGET=dns-monitor
SOURCES=$(wildcard *.cpp)
OBJECTS=$(SOURCES:.cpp=.o)

# Link the target with all objects files
$(TARGET): $(OBJECTS)
	$(CXX) $(CXXFLAGS) $(OBJECTS) -o $@ $(LDFLAGS)

# Compile each source file to an object
%.o: %.cpp
	$(CXX) $(CXXFLAGS) -c $< -o $@

# Clean up the build
clean:
	rm -f $(TARGET) $(OBJECTS)

# Phony targets for commands that do not represent files
.PHONY: clean