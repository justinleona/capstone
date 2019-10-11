#pragma once

#include <capstone/capstone.h>
#include <iterator>

class Capstone {
  size_t handle;
  size_t size;
  const uint8_t* code;
  uint64_t address;

 public:
  Capstone(csh handle, const uint8_t* code, size_t size, uint64_t address);
  ~Capstone();

  /* 
   * provide the ability to iterate over parse instructions produced incrementally -
   * each instruction is parsed on demand using cs_disasm_iter.  The containing object
   * must remain valid as long as the cs_insn is referenced.
   */
  class const_iterator {
    size_t handle;
    cs_insn* insn;
    const uint8_t* code;
    size_t size;
    uint64_t address;

   public:
    /* these provide compatibility with standard algorithms by defining crucial characteristics of this iterator */
    using iterator_category = std::input_iterator_tag;
    using value_type = cs_insn;
    using difference_type = long;
    using pointer = cs_insn*;
    using reference = cs_insn&;

    //don't allow implicit conversions to iterator
    explicit const_iterator(const Capstone& c);

    //allow for copying the iterator to "save" the location in the buffer - it's okay if we disassemble 
    //the same fragment multiple times this way
    const_iterator(const const_iterator& copy);

    const_iterator();
    ~const_iterator();

    const cs_insn& operator*() const;
    const_iterator& operator++();
    const_iterator operator++(int);

    friend long operator-(const_iterator const& lhs, const_iterator const& rhs);
    friend bool operator==(const_iterator const& lhs, const_iterator const& rhs);
    friend bool operator!=(const_iterator const& lhs, const_iterator const& rhs);
  };

  const_iterator begin() const;
  const_iterator end() const;
};
