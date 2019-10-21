#pragma once

#include "tracehandler.h"

class trace_exception : public std::exception {
  const std::string trc;
  const std::string msg;
 public:
  trace_exception(const char* msg) : trc(StackTraceHandler::getTrace(3)), msg(msg) {}
  trace_exception(const std::string& msg) : trc(StackTraceHandler::getTrace(3)), msg(msg) {}

  const std::string& trace() const noexcept { return trc; }
  const char* what() const noexcept { return msg.c_str(); }
};
