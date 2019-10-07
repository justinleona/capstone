#include "capstone.h"
#include <functional>
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

vector<cs_insn> capstone::disasm(const vector<uint8_t>& code, uint64_t address, size_t count) {
  cs_insn* insn;
  size_t size = cs_disasm(handle, code.data(), code.size(), address, count, &insn);
  auto p = shared_ptr<cs_insn>(insn, bind(cs_free, _1, size));

  // this is relatively heavy since it copies all the structs...
  // it also doesn't guarantee safety since the internal structs include
  // pointers but it does make the return intrinsically iterable
  return std::vector<cs_insn>(insn, insn + size);
}
