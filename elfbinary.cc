#include "elfbinary.h"
#include <algorithm>
#include <fstream>
#include <iomanip>
#include <iostream>
#include <range/v3/all.hpp>

using namespace std;

ElfBinary::ElfBinary() {}

ElfBinary::ElfBinary(Indent& indent) : Indentable(indent) {}

size_t ElfBinary::getSectionHeaderOffset() {
  return header.e_shoff;
}

size_t ElfBinary::getSectionHeaderCount() {
  return header.e_shnum;
}

size_t ElfBinary::getStringTableIndex() {
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

  auto section_table_count = hdr.e_shnum;
  auto section_offset = hdr.e_shoff;

  Elf64_Shdr init;
  ist.seekg(section_offset);
  ist.read((char*)&init, sizeof(Elf64_Shdr));
  if (section_table_count == 0x0) {
    section_table_count = init.sh_size;
  }
  elf.sections.push_back(init);

  for(int i=1; i<section_table_count; ++i) 
  {
    Elf64_Shdr s;
    ist.read((char*)&s, sizeof(Elf64_Shdr));
    elf.sections.push_back(s);
  }

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

const vector<Elf64_Shdr>& ElfBinary::getSections() {
  return sections;
}

// vector<string> ElfBinary::parseSectionNames(istream& ist) {
// const vector<char>& v = getSectionNames(ist);
// string buf;
// vector<string> section_names;
// for (char c : v) {
// buf += c;
// if (c == '\0') {
// section_names.push_back(buf);
// buf = "";
//}
//}
// return section_names;
//}

vector<char> ElfBinary::getSectionNames(istream& ist) {
  auto section_table_index = header.e_shstrndx;

  // needs to handle SHN_XINDEX

  const ElfSectionHeader& str_table = sections[section_table_index];
  auto offset = str_table.getOffset();
  auto size = str_table.getSize();

  ist.seekg(offset);
  vector<char> section_names(size);
  ist.read(section_names.data(), size);
  return section_names;
}
