#pragma once

#include <iostream>

/**
 * Implement basic semantics of a buffer around a static array 
 */
class charbuf : public std::streambuf {
 public:
  charbuf(char* s, size_t n);

  std::streampos seekpos(std::streampos pos, std::ios_base::openmode which);
  std::streampos seekoff(std::streamoff off, std::ios_base::seekdir way, std::ios_base::openmode which);
  std::streambuf* setbuf(char* s, std::streamsize n);
  int underflow();
  int pbackfail(int c);
  int overflow(int c);
};

/**
 * Wrap a simple char array into a stream we can operate on with standard insertion/extraction
 */
class charstream : public std::istream, public std::ostream {
  charbuf b;

 public:
  charstream(char* s, size_t n);
};
