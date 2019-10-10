#include "capstone.h"
#include <functional>
#include <iostream>
#include <memory>
#include <string>

using namespace std;
using namespace std::placeholders;

capstone::capstone(cs_arch arch, cs_mode mode) {
  cs_err err = cs_open(CS_ARCH_X86, CS_MODE_64, &handle);
  if (err != CS_ERR_OK)
    throw string(cs_strerror(err));
  cs_option(handle, CS_OPT_DETAIL, CS_OPT_ON);
}

void capstone::setAtt() {
  cs_option(handle, CS_OPT_SYNTAX, CS_OPT_SYNTAX_ATT);
}

capstone::~capstone() {
  cs_close(&handle);
}

vector<cs_insn> capstone::disasm(const uint8_t* code, size_t size, uint64_t address, size_t count) {
  cs_insn* insn;
  cout << "attempting to parse: " << hex << size << " bytes" << endl;
  size_t i_sz = cs_disasm(handle, code, size, address, count, &insn);

  //this doesn't work because it de-allocs the underlying cs_insn as well ><
  //auto p = shared_ptr<cs_insn>(insn, bind(cs_free, _1, size));
  cout << "parsed instructions: " << hex << i_sz << endl;

  //copy of each element in a vector
  return vector<cs_insn>(insn, insn+i_sz);
}
