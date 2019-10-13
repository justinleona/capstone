#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>
#include "capstone.h"
#include "capstonebuilder.h"
#include "elfbinary.h"
#include "indent.h"
#include "static_cast.h"

using namespace std;

void dumpBytes(uint8_t bytes[], size_t size, uint64_t offset) {
  cout << hex << setfill('0') << setw(8) << (unsigned int)offset << ": ";
  for (uint64_t i = 0; i != size; ++i) {
    if (i > 0 && i % 16 == 0)
      cout << endl << hex << setfill('0') << setw(8) << (unsigned int)(i + offset) << ": ";
    else if (i > 0 && i % 2 == 0)
      cout << " ";
    cout << hex << setfill('0') << setw(2) << (unsigned int)bytes[i];
  }
  cout << endl;
}

/*
 * trivial decompiler for a block of raw bytes using the capstone library
 */
int main() {
  try {
    ifstream ist("/usr/bin/ls", ifstream::binary);

    Indent indent;
    ElfBinary elf(indent);
    ist >> elf;
    cout << elf;

    const vector<char>& names = elf.getSectionNames(ist);
    const vector<ElfSectionHeader>& sections = elf.getSections(ist);

    CapstoneBuilder csb;
    csb.setAtt();
    for (const ElfSectionHeader& h : sections) {
      auto index = h.getNameIndex();

      cout << index << endl;
      if (index >= names.size()) {
        throw "invalid name index";
      }

      string name(&names[index]);
      if (name == ".text") {
        auto size = h.getSize();
        auto offset = h.getOffset();

        uint8_t bytes[size];
        ist.seekg(offset);
        ist.read((char*)bytes, size);

        // dumpBytes(bytes, size, offset);

        csb.setAddress(offset);
        for (const cs_insn& i : csb(bytes,size)) {
          cout << indent << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << endl;
        }
      }
    }
    return 0;
  } catch (char const* msg) {
    cerr << msg << endl;
    return 1;
  }
}
