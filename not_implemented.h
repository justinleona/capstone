#pragma once

#include <stdexcept>
#include <string>

class not_implemented : public std::logic_error {
 public:
  not_implemented() : not_implemented("not yet implemented") {}
  not_implemented(const std::string& m) : logic_error(m) {}
};
