#include "charstream.h"
#include <iomanip>
#include "not_implemented.h"
#include "stacktracehandler.h"

using namespace std;

charbuf::charbuf(char* s, size_t n, size_t offset) : offset(offset) {
  auto begin = s;
  auto c = s;
  auto end = s + n;

  // set begin, current, and end states for reading
  setg(begin, c, end);
  setp(begin, end);
}

streampos charbuf::seekpos(streampos pos, ios_base::openmode which) {
  const pos_type& rel = pos - pos_type(off_type(offset));

  StackTraceHandler::printTrace();

  bool in = which & ios_base::openmode::_S_in;
  cout << "seekpos(" << hex << pos << ", in=" << in << ")" << endl;
  return seekoff(rel, ios_base::beg, which);
}

long repos(streamoff pos, char* begin, char* cur, char* end, ios_base::seekdir way) {
  switch (way) {
    case ios_base::beg:
      return begin + pos - cur;
      break;
    case ios_base::cur:
      return pos;
      break;
    case ios_base::end:
      return end + pos - cur;
      break;
    default:
      break;
  }
  return -1;
}

streampos charbuf::seekoff(streamoff pos, ios_base::seekdir way, ios_base::openmode which) {
  bool in = which & ios_base::openmode::_S_in;
  cout << "seekoff(" << hex << pos << "," << way << ", in=" << in << ")" << endl;

  // no separate begin/end - single array in memory
  char* begin = eback();
  char* end = egptr();
  long goff = repos(pos, begin, gptr(), end, way);
  long poff = repos(pos, begin, pptr(), end, way);
  char* cg = gptr() + goff;
  char* cp = pptr() + poff;

  // cout << "gptr=" << hex << (uint64_t)gptr() << " goffset=" << goff << endl;

  bool set = false;
  if (which & ios_base::in) {
    if (begin <= cg && cg < end) {
      gbump(goff);
      set = true;
    }
  }
  if (which & ios_base::out) {
    if (begin <= cp && cp < end) {
      pbump(poff);
      set = true;
    }
  }

  if (set) {
    return gptr() - begin;
  }
  return -1;
}

// below are implemented so we know if we're using features we'd expect to provide but don't!
streambuf* charbuf::setbuf(char* s, streamsize n) {
  // cerr << "setbuf not yet implemented" << endl;
  throw not_implemented{"setbuf not yet implemented!"};
}

int charbuf::underflow() {
  // cerr << "underflow not yet implemented" << endl;
  throw not_implemented{"underflow not yet implemented!"};
}

int charbuf::pbackfail(int c) {
  // cerr << "pbackfail not yet implemented" << endl;
  throw not_implemented{"pbackfail not yet implemented!"};
}

int charbuf::overflow(int c) {
  // cerr << "overflow not yet implemented" << endl;
  throw not_implemented{"overflow not yet implemented!"};
}

charstream::charstream(char* s, size_t n, size_t offset) : istream(&b), ostream(&b), b(s, n, offset) {
  rdbuf(&b);
}

charstream::charstream(uint8_t* s, size_t n, size_t offset) : charstream((char*)s, n, offset) {}

void dumpBytes(uint8_t bytes[], size_t size, uint64_t offset) {
  cout << hex << setfill('0') << setw(8) << (unsigned int)offset << ": ";
  for (uint64_t i = 0; i != size; ++i) {
    if (i > 0 && i % 16 == 0)
      cout << endl << hex << setfill('0') << setw(8) << (unsigned int)(i + offset) << ": ";
    else if (i > 0 && i % 2 == 0)
      cout << " ";
    cout << hex << setfill('0') << setw(2) << (unsigned int)bytes[i];
  }
  cout << endl;
}
