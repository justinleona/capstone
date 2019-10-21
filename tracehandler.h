#pragma once

#include <ostream>

class StackTraceHandler {
 public:
  /* Handle segmentation faults with a stack trace */
  StackTraceHandler();
  ~StackTraceHandler();

  /* Attempt to print a pretty backtrace to std::cerr with demangled names */
  static void printTrace(std::ostream& ost, int skip);
  static std::string getTrace(int skip);
};
