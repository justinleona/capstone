#include <capstone/capstone.h>
#include <elf.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include "capstone.h"

using namespace std;

typedef istream_iterator<char> ist_iter;

template <typename T>
struct StaticCast {
  template <typename U>
  T operator()(const U& rhs) {
    return static_cast<T>(rhs);
  }
};

/*
 * trivial decompiler for a block of raw bytes using the capstone library
 */
int main() {
  // this object must be valid for any reference to any capstone type - e.g.,
  // cs_insn
  capstone cs(CS_ARCH_X86, CS_MODE_64);
  cs.setAtt();

  vector<uint8_t> code;
  ifstream ist("./myapp", std::ifstream::binary);
  transform(ist_iter(ist), ist_iter(), back_inserter(code), StaticCast<uint8_t>());

  cout << hex;
  for (const auto& i : cs.disasm(code, 0x1000, 0))
    std::cout << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << std::endl;
  return 0;
}
