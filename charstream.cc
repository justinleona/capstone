#include "charstream.h"

using namespace std;

charbuf::charbuf(char* s, size_t n) {
  // set begin, current, and end states for reading
  setg(s, s, s + n);
  setp(s,s+n);
}

streampos charbuf::seekpos(streampos pos, ios_base::openmode which) {
  if (which & ios_base::in && which & ios_base::out) {
    //we don't have separate buffers for in+out
    char* begin = eback();
    char* c = begin + pos;
    char* end = egptr();

    if (begin <= c && c < end) {
      setg(begin, c, end);
      setp(c, end);
      return pos;
    }
  }
  else if (which & ios_base::in) {
    char* begin = eback();
    char* c = begin + pos;
    char* end = egptr();

    if (begin <= c && c < end) {
      setg(begin, c, end);
      return pos;
    }
  }
  else if (which & ios_base::out) {
    char* begin = pbase();
    char* c = begin + pos;
    char* end = epptr();

    if (begin <= c && c < end) {
      setp(c, end);
      return pos;
    }
  }
  return -1;
}

// below are implemented so we know if we're using features we'd expect to provide but don't!
streampos charbuf::seekoff(streamoff pos, ios_base::seekdir way, ios_base::openmode which) {
  throw "seekoff not yet implemented!";
}

streambuf* charbuf::setbuf(char* s, streamsize n) {
  throw "setbuf not yet implemented!";
}

int charbuf::underflow() {
  throw "underflow not yet implemented!";
}

int charbuf::pbackfail(int c) {
  throw "pbackfail not yet implemented!";
}

int charbuf::overflow(int c) {
  throw "overflow not yet implemented!";
}

charstream::charstream(char* s, size_t n) : istream(&b), ostream(&b), b(s, n) {
  rdbuf(&b);
}
