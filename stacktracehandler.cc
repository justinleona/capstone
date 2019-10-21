#include "stacktracehandler.h"
#include <cxxabi.h>
#include <execinfo.h>
#include <signal.h>
#include <unistd.h>
#include <iostream>
#include "unique_cptr.h"

using namespace std;

unique_cptr<char> demangle(const string &str, int *status) {
  auto c = str.c_str();
  return unique_cptr<char>{abi::__cxa_demangle(c, nullptr, 0, status)};
}

void handler(int sig) {
  // this is safer for memory restricted conditions
  constexpr int n{64};
  void *frames[n];  // most programs will never get this deep

  const int size{backtrace(frames, n)};
  cerr << "Stackframes {" << size << "}: " << endl;
  backtrace_symbols_fd(frames, size, STDERR_FILENO);
}

StackTraceHandler::StackTraceHandler() {
  signal(SIGSEGV, handler);
}

StackTraceHandler::~StackTraceHandler() {
  signal(SIGSEGV, SIG_DFL);
}

//attempt to create prettier backtrace with demangled names - this may fail if memory is limited
void StackTraceHandler::printTrace() {
  constexpr int n{64};
  void *frames[n];

  const int size{backtrace(frames, n)};
  if( size <= 1 ) 
    throw std::runtime_error("failed to retrieve backtrace");

  unique_cptr<char *[]> symbols { backtrace_symbols(frames, size) };
  if (symbols.get() == nullptr)
    throw std::runtime_error("failed to retrieve backtrace symbols");

  //omit this function from trace
  cerr << "Stackframes {" << size-1 << "}: " << endl;
  for (int i = 1; i != size; ++i) {
    string mangled{symbols[i]};
    auto begin = mangled.find("(_") + 1;
    auto len = mangled.find_last_of('+') - begin;
    auto func = mangled.substr(begin, len);

    int status;
    unique_cptr<char> name{demangle(func, &status)};

    if (status != 0)
      cerr << mangled << endl;
    else
      cerr << mangled.replace(begin, len, name.get()) << endl;
  }
}
