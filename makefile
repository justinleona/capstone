EXE = myapp

CXX := clang++ -std=c++2a
SRC := $(wildcard *.cc)
OBJ := $(SRC:%.cc=%.o)
ASM := $(SRC:%.cc=%.s)
DEP := $(SRC:%.cc=%.d)

CPPFLAGS += -ggdb
LDFLAGS += -no-pie
LDLIBS += -lcapstone

all: $(EXE) $(ASM)

$(EXE): $(OBJ)
	$(CXX) $(LDFLAGS) $(OBJ) -o $@ $(LDLIBS)

%.o:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) -c $< -o $@

%.s:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) -S $< -o $@

%.d:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) $< -MM >$@

clean:
	-rm *.o
	-rm *.s
	-rm *.d
	-rm myapp

-include $(DEP)
