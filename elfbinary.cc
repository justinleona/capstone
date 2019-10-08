#include "elfbinary.h"
#include <iostream>
#include <fstream>
#include <algorithm>

using namespace std;

istream& operator>>(istream& ist, ElfBinary& elf) 
{
  ist.seekg(0);
  ist.read((char*)&elf.header, sizeof(Elf64_Ehdr));
  return ist;
}

ostream& operator<<(ostream& ost, const ElfBinary& elf) {
  auto section_offset = elf.header.e_shoff;
  auto section_table_count = elf.header.e_shnum;
  auto section_table_index = elf.header.e_shstrndx;
  auto section_size = elf.header.e_shentsize;

  ost << dec;
  ost << "section header offset " << section_offset << endl;
  ost << "section header string table index: " << section_table_index << endl;
  ost << "section table count: " << section_table_count << endl;
  ost << "section entry size: " << section_size << endl;
  return ost;
}

vector<ElfSectionHeader> ElfBinary::getSections(istream& ist)
{
  auto section_table_count = header.e_shnum;
  auto section_offset = header.e_shoff;

  vector<Elf64_Shdr> headers(section_table_count);
  ist.seekg(section_offset);
  ist.read((char*)headers.data(), headers.size() * sizeof(Elf64_Shdr));

  vector<ElfSectionHeader> sections;
  transform(headers.begin(), headers.end(), back_inserter(sections), ElfSectionHeader::create);
  return sections;
}

vector<string> ElfBinary::getSectionNames(istream& ist) {
  auto section_offset = header.e_shoff;
  auto section_table_entry_size = header.e_shentsize;
  auto section_table_count = header.e_shnum;
  auto section_table_index = header.e_shstrndx;
  auto section_size = header.e_shentsize;

  const auto& headers = getSections(ist);
  const auto& str_table = headers[section_table_index];

  auto offset = str_table.getOffset();
  auto size = str_table.getSize();

  cout << hex;
  cout << "string table offset: " << offset << endl;
  cout << "string table size: " << size << endl;

  ist.seekg(offset);
  vector<string> section_names;
  for (unsigned int i = 0, j = 0; i != section_table_count; ++i) {
    string str;
    for (unsigned int k = 0; j != size && k != section_table_entry_size; ++j, ++k) {
      char c = ist.get();
      if (c == '\0')
        break;
      str += c;
    }
    section_names.push_back(str);
  }

  return section_names;
}
