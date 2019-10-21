#include <fstream>
#include <iostream>
#include "capstonebuilder.h"
#include "elfsectionheaders.h"
#include "indent.h"
#include "stacktracehandler.h"
#include "traceexception.h"

using namespace std;

/*
 * trivial decompiler for a block of raw bytes using the capstone library
 */
int main() {
  StackTraceHandler handler;

  try {
    ifstream ist("/usr/bin/ls", ifstream::binary);

    Indent indent;
    ElfBinary elf(indent);
    ElfSectionHeaders headers(elf, indent);

    ist >> elf;
    ist >> headers;

    cout << elf;

    CapstoneBuilder csb;
    csb.setAtt();

    for (const auto& h : headers) {
      if (h.name() == ".text") {
        auto size = h.getSize();
        auto offset = h.getOffset();

        uint8_t bytes[size];
        ist.seekg(offset);
        ist.read((char*)bytes, size);

        // dumpBytes(bytes, size, offset);

        csb.setAddress(offset);
        for (const cs_insn& i : csb(bytes, size)) {
          cout << indent << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << endl;
        }
      }
    }
    return 0;
  } catch (const trace_exception& e) {
    cerr << e.what() << endl;
    cerr << e.trace() << endl;
    return 1;
  }
}
