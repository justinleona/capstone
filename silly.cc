#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include "capstone.h"
#include "capstonebuilder.h"
#include "elfbinary.h"
#include "indent.h"
#include "static_cast.h"

using namespace std;

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

    CapstoneBuilder csb;
    csb.setAtt();

    const vector<Elf64_Shdr>& headers = elf.getSections();
    vector<Elf64_Shdr>::const_iterator end = headers.end();
    for(vector<Elf64_Shdr>::const_iterator i = headers.begin(); i != end; ++i)
    {
      const ElfSectionHeader& h = *i;
      auto index = h.getNameIndex();
      cout << h;

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
