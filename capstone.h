#pragma once

#include <capstone/capstone.h>
#include <vector>

class capstone { 
    csh handle;
public:
    capstone(cs_arch arch, cs_mode mode);
    ~capstone();

    void setAtt();

    /** 
     * Return a smart pointer to the disassembled contents of a passed vector, with addresses starting as indicated.  Will attempt to parse at most count instructions, or all if 0.
     */
    std::vector<cs_insn> disasm(const uint8_t* code, size_t size, uint64_t address, size_t count);

    cs_insn disasm(uint8_t code, uint64_t address);
};
