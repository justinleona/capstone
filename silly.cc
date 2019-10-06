#include <stdio.h>
#include <iostream>
#include <capstone/capstone.h>
#include <vector>

using namespace std;

/*
 * trivial decompiler for a block of raw bytes using the capstone library
 */
int main() 
{
    csh handle;
    cs_insn *insn;
    
    if( cs_open(CS_ARCH_X86, CS_MODE_64, &handle) != CS_ERR_OK) 
        return -1;

    const uint8_t code[] = {0x55,0x48,0x8b,0x05,0xb8,0x13,0x00,0x00};
    auto count = cs_disasm(handle,code, sizeof(code), 0x1000, 0, &insn);

    std::cout << std::hex;
    for(auto i : std::vector<cs_insn>(insn, insn+count)) 
        std::cout << "0x" << i.address << " " << i.mnemonic << " " << i.op_str << std::endl;
    cs_close(&handle);

    return 0;
}
