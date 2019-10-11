#pragma once

#include <capstone/capstone.h>
#include "capstone.h"

class CapstoneBuilder {
  cs_arch arch = CS_ARCH_X86;
  cs_mode mode = CS_MODE_64;
  uint64_t address = 0x0;
  bool att = false;

 public:
  CapstoneBuilder();

  CapstoneBuilder& setArchitecture(cs_arch arch);
  CapstoneBuilder& setMode(cs_mode mode);
  CapstoneBuilder& setAtt(bool att = true);
  CapstoneBuilder& setAddress(uint64_t address);

  /**
   * create a capstone instance bound to a specific fragment of code with the provided configurations
   */
  Capstone operator()(const uint8_t* code, size_t size);
};
