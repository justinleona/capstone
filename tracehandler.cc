#include "tracehandler.h"
#include <cxxabi.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <iostream>
#include <sstream>
#include "unique_cptr.h"

using namespace std;

void demangle(string &mangled) {
  auto begin = mangled.find("(_") + 1;
  auto len = mangled.find_last_of('+') - begin;
  auto func = mangled.substr(begin, len);
  auto c = func.c_str();

  // let demangle alloc it's own memory
  int status;
  unique_cptr<char> name{abi::__cxa_demangle(c, nullptr, 0, &status)};

  if (status == 0)
    mangled.replace(begin, len, name.get());
}

void handler(int sig) {
  StackTraceHandler::printTrace(cerr,2);

  //// this is safer for memory restricted conditions
  // constexpr int n{64};
  // void *frames[n];  // most programs will never get this deep

  // const int size{backtrace(frames, n)};
  // cerr << "Stackframes {" << size << "}: " << endl;
  // backtrace_symbols_fd(frames, size, STDERR_FILENO);
}

StackTraceHandler::StackTraceHandler() {
  signal(SIGSEGV, handler);
}

StackTraceHandler::~StackTraceHandler() {
  signal(SIGSEGV, SIG_DFL);
}

// attempt to create prettier backtrace with demangled names - this may fail if memory is limited
void StackTraceHandler::printTrace(ostream &ost, int skip) {
  constexpr int n{64};
  void *frames[n];

  const int size{backtrace(frames, n)};
  if (size <= 1)
    throw std::runtime_error("failed to retrieve backtrace");

  unique_cptr<char *[]> symbols { backtrace_symbols(frames, size) };
  if (symbols.get() == nullptr)
    throw std::runtime_error("failed to retrieve backtrace symbols");

  // omit this function from trace
  for (int i = skip; i != size; ++i) {
    if (symbols[i] != nullptr) {
      string mangled{symbols[i]};
      demangle(mangled);
      ost << mangled << endl;
    }
  }
}

string StackTraceHandler::getTrace(int skip) {
  stringstream ss;
  printTrace(ss, skip);
  return ss.str();
}
