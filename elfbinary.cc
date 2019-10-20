#include "elfbinary.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <range/v3/all.hpp>

using namespace std;

ElfBinary::ElfBinary() {}

ElfBinary::ElfBinary(Indent& indent) : Indentable(indent) {}

size_t ElfBinary::getSectionHeaderOffset() const {
  return header.e_shoff;
}

size_t ElfBinary::getSectionHeaderCount() const {
  return header.e_shnum;
}

size_t ElfBinary::getStringTableIndex() const {
  return header.e_shstrndx;
}

istream& operator>>(istream& ist, ElfBinary& elf) {
  auto& hdr = elf.header;

  ist.seekg(0);
  ist.read((char*)&hdr, sizeof(Elf64_Ehdr));

  if (!ist)
    throw "failed to read complete Elf header";
  if (hdr.e_ident[0] != 0x7f || hdr.e_ident[1] != 'E' || hdr.e_ident[2] != 'L' || hdr.e_ident[3] != 'F')
    throw "magic string failed";
  return ist;
}

ostream& operator<<(ostream& ost, const ElfBinary& elf) {
  Indent& i = elf.indent;
  auto section_offset = elf.header.e_shoff;
  auto section_table_count = elf.header.e_shnum;
  auto section_table_index = elf.header.e_shstrndx;
  auto section_size = elf.header.e_shentsize;

  ost << i++ << "Elf {" << endl;
  ost << i << hex << "section header offset 0x" << section_offset << endl;
  ost << i << dec << "section header string table index: " << section_table_index << endl;
  ost << i << hex << "section table count: 0x" << section_table_count << endl;
  ost << i << "section entry size: 0x" << section_size << endl;
  ost << --i << "}" << endl;
  return ost;
}
