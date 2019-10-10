EXE = myapp

OBJDIR = obj
ASMDIR = asm
CXX := clang++ -std=c++2a
SRC := $(wildcard *.cc)
OBJ := $(SRC:%.cc=$(OBJDIR)/%.o)
ASM := $(SRC:%.cc=$(ASMDIR)/%.s)
DEP := $(SRC:%.cc=$(OBJDIR)/%.d)

CPPFLAGS += -ggdb
LDFLAGS += -no-pie
LDLIBS += -lcapstone

all: $(EXE) $(ASM)

$(EXE): $(OBJ)
	$(CXX) $(LDFLAGS) $(OBJ) -o $@ $(LDLIBS)

$(OBJDIR)/%.o:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) -c $< -o $@

$(ASMDIR)/%.s:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) -S $< -o $@

$(OBJDIR)/%.d:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) $< -MM >$@

clean:
	-rm $(OBJDIR)/*.o
	-rm $(ASMDIR)/*.s
	-rm $(OBJDIR)/*.d
	-rm myapp

-include $(DEP)
