#pragma once

#include <stdexcept>
#include <string>
#include "traceexception.h"

class not_implemented : public trace_exception {
 public:
  not_implemented() : trace_exception("not yet implemented") {}
  not_implemented(const std::string& m) : trace_exception(m) {}
};
