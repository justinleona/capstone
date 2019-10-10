#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <vector>
#include "capstone.h"
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
    capstone cs(CS_ARCH_X86, CS_MODE_64);
    cs.setAtt();
    ifstream ist("/usr/bin/ls", ifstream::binary);

    Indent indent;
    ElfBinary elf(indent);
    ist >> elf;
    cout << elf;

    const vector<char>& names = elf.getSectionNames(ist);
    const vector<ElfSectionHeader>& sections = elf.getSections(ist);
    //for (const ElfSectionHeader& h : sections) {
      //cout << indent++ << h;
      //cout << --indent << endl;
    //}

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

        //const auto& v = cs.disasm(bytes, size, offset, 0);
        // for (const auto& i : v)
        // cout << indent << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << endl;
        // cout << --indent << "};" << endl;
      }
      //--indent;
      //cout << endl;
    }
    return 0;
  } catch (char const* msg) {
    cerr << msg << endl;
    return 1;
  }

  /*
    int i = 0;
    cout << indent++ << "section header names" << endl;
    for (auto str : names)
      cout << indent << dec << i++ << ": " << str << endl;

    cout << elf;
    for (auto hdr : s)
      cout << hdr;

    ist.seekg(execution_entry);
    transform(ist_iter(ist), ist_iter(), back_inserter(bin), static_cast_f<uint8_t>());

    for (const auto& i : cs.disasm(bin, 0x1000, 0))
      std::cout << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << std::endl;
  */
}
