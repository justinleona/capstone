#include <bits/stdc++.h>
#include "catch.hpp"
#include "charstream.h"
#include "elfbinary.h"

using namespace std;

TEST_CASE("ElfBinary loads headers", "[elfbinary]") {
  // in vim we get this with s/\(..\)/0x\1,/ on the encoded blob from xxd
  uint8_t s[]{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
              0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0b, 0x00, 0x40, 0x00, 0x1d, 0x00, 0x1c, 0x00};

  uint64_t off = 0x21720; //snipped
  uint8_t shdr[]{0x67, 0x6c, 0x69, 0x6e, 0x6b, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x0b, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00,
                 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0xa8, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x1c, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x13, 0x00, 0x00, 0x00, 0x07, 0x00, 0x00, 0x00,
                 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0xc4, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  ElfBinary bin;
  SECTION("verify magic number mismatch") {
    // chew a byte to screw up the ELF magic string
    charstream ist(s, sizeof(s));
    s[1] = 0x4c;
    CHECK_THROWS((ist >> bin));
  }

  SECTION("verify magic number match") {
    charstream ist(s, sizeof(s));
    ist >> bin;

    REQUIRE(bin.getSectionHeaderOffset() == 137000);
    REQUIRE(bin.getSectionHeaderCount() == 29);
    REQUIRE(bin.getStringTableIndex() == 28);
  }

  SECTION("verify headers loading") {
    charstream ist(s, sizeof(s));

    // moc out a simpler structure to put in code
    Elf64_Ehdr moc;
    ist.read((char*)&moc, sizeof(Elf64_Ehdr));
    moc.e_shoff -= off;
    moc.e_shnum = 2;    // init header + 1
    ist.write((char*)&moc, sizeof(Elf64_Ehdr));

    ist >> bin;
    REQUIRE(bin.getSectionHeaderCount() == 2);
    REQUIRE(bin.getSectionHeaderOffset() == 0x8);

    // move to hdr stream
    ist = charstream(shdr, sizeof(shdr));
    charstream_iterator<Elf64_Shdr> v = bin.getSections(ist);

    ElfSectionHeader init(*v);
    REQUIRE( init.getOffset() == 0x0 );
    REQUIRE( init.getSize() == 0x0 );

    //this creates a lot of copies, but should still work
    //REQUIRE(v[0].sh_offset == 0x0);
    //REQUIRE(v[0].sh_size == 0x0);
    //REQUIRE(v[1].sh_offset == 0x2a8);
    //REQUIRE(v[1].sh_size == 0x1c);

    //++v;
    //ElfSectionHeader hdr(*v);
    //REQUIRE( hdr.getOffset() == 0x2a8 );
    //REQUIRE( hdr.getSize() == 0x1c );
  }
}
