#include <iostream>
#include <fstream>
#include <vector>
#include "capstone.h"
#include "static_cast.h"
#include "elfbinary.h"

using namespace std;

/*
 * trivial decompiler for a block of raw bytes using the capstone library
 */
int main() {
  capstone cs(CS_ARCH_X86, CS_MODE_64);
  cs.setAtt();

  ifstream ist("/usr/bin/ls", std::ifstream::binary);

  ElfBinary elf;
  ist >> elf;
  for(string s : elf.getSectionNames(ist)) 
  {
    cout << "string table name: " << s << endl;
  }

/*
 *  ist.seekg(execution_entry);
 *  transform(ist_iter(ist), ist_iter(), back_inserter(bin), static_cast_f<uint8_t>());
 *
 *  for (const auto& i : cs.disasm(bin, 0x1000, 0))
 *    std::cout << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << std::endl;
 */
  return 0;
}
