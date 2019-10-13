EXE = myapp
CATCH = catch
OBJDIR = obj
ASMDIR = asm
CXX := clang++ -std=c++2a
SRC := $(wildcard *.cc)
ASM := $(SRC:%.cc=$(ASMDIR)/%.s)
DEP := $(SRC:%.cc=$(OBJDIR)/%.d)

CPPFLAGS += -ggdb
LDFLAGS += -no-pie
LDLIBS += -lcapstone

all: $(EXE) $(CATCH) $(ASM)

$(EXE): $(filter-out $(OBJDIR)/catch.o, $(SRC:%.cc=$(OBJDIR)/%.o))
	$(CXX) $(LDFLAGS) $? -o $@ $(LDLIBS)

$(CATCH): $(filter-out $(OBJDIR)/silly.o, $(SRC:%.cc=$(OBJDIR)/%.o))
	$(CXX) $(LDFLAGS) $? -o $@ $(LDLIBS)

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
	-rm $(EXE)
	-rm $(CATCH)

-include $(DEP)
