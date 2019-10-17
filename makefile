EXE = myapp
CATCH = catch
CXX := clang++-9 -std=c++2a
TST := $(wildcard *test.cc)
SRC := $(filter-out $(TST), $(wildcard *.cc))

CPPFLAGS += -ggdb
LDFLAGS += -no-pie
LDLIBS += -lcapstone

all: $(EXE) $(CATCH)

test: $(CATCH)
	./$(CATCH)

# this let's us print make variables easily for debugging
print-% : ; @echo $* = $($*)

$(EXE):$(SRC:%.cc=obj/%.o)
	$(CXX) $(LDFLAGS) $^ -o $(EXE) $(LDLIBS)

$(CATCH):$(filter-out obj/silly.o, $(SRC:%.cc=obj/%.o)) $(TST:%.cc=obj/%.o)
	$(CXX) $(LDFLAGS) $^ -o $(CATCH) $(LDLIBS)

obj/%.o:%.cc obj/%.d
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) -c $< -o $@

# technically .d should depend on .cc and .h as well, this might occasionally necessitate full rebuilds
obj/%.d:%.cc
	$(CXX) $(CPPFLAGS) $(CXXFLAGS) $(CFLAGS) $< -MM >$@

clean:
	-rm obj/*.o
	-rm asm/*.s
	-rm obj/*.d
	-rm $(EXE)
	-rm $(CATCH)

include $(wildcard *.cc:%.cc=obj/%.d)
