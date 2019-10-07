#include <capstone/capstone.h>
#include <elf.h>
#include <algorithm>
#include <fstream>
#include <iostream>
#include <iterator>
#include <vector>
#include "capstone.h"
#include "static_cast.h"

using namespace std;

typedef istream_iterator<char> ist_iter;

/*
 * trivial decompiler for a block of raw bytes using the capstone library
 */
int main() {
  capstone cs(CS_ARCH_X86, CS_MODE_64);
  cs.setAtt();

  vector<uint8_t> bin;
  ifstream ist("/usr/bin/ls", std::ifstream::binary);

  Elf64_Ehdr header;
  ist.read((char*)&header, sizeof(Elf64_Ehdr));

  auto execution_entry = header.e_entry;
  auto section_offset = header.e_shoff;
  auto section_table_entry = header.e_shentsize;
  auto section_table_count = header.e_shnum;
  auto section_table_index = header.e_shstrndx;
  auto section_size = header.e_shentsize;

  cout << dec;
  cout << "section header offset " << section_offset << endl;
  cout << "section header string table index: " << section_table_index << endl;
  cout << "section table count: " << section_table_count << endl;
  cout << "section entry size: " << section_size << endl;

  vector<Elf64_Shdr> headers(section_table_count);
  ist.seekg(section_offset);
  ist.read((char*)headers.data(), headers.size()*sizeof(Elf64_Shdr));

  const auto& str_table = headers[section_table_index];
  auto offset = str_table.sh_offset;
  auto size = str_table.sh_size;

  cout << hex;
  cout << "string table offset: " << offset << endl;
  cout << "string table size: " << size << endl;
  
  ist.seekg(offset);
  vector<string> section_names;
  for(int i=0; i!=section_table_count; ++i) {
    string str;
    getline(ist, str, '\0');
    section_names.push_back(str);
  }

  cout << "string table name: " << section_names[str_table.sh_name] << endl;

/*
 *  ist.seekg(execution_entry);
 *  transform(ist_iter(ist), ist_iter(), back_inserter(bin), static_cast_f<uint8_t>());
 *
 *  for (const auto& i : cs.disasm(bin, 0x1000, 0))
 *    std::cout << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << std::endl;
 */
  return 0;
}
