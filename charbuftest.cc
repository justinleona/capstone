#include "catch.hpp"
#include "charstream.h"

using namespace std;

TEST_CASE("Charbuf works for basic ops", "[charstream]") {
  // in vim we get this with s/\(..\)/0x\1,/ on the encoded blob from xxd
  char s[]{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x03, 0x00, 0x3e, 0x00, 0x01, 0x00, 0x00, 0x00, 0x30, 0x61, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x28, 0x17, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x38, 0x00, 0x0b, 0x00, 0x40, 0x00, 0x1d, 0x00, 0x1c, 0x00,
           0x06, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x40, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x68, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x68, 0x02, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
           0x08, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x03, 0x00, 0x00, 0x00, 0x04, 0x00, 0x00, 0x00};

  charstream st(s, sizeof(s));

  SECTION("read test") {
    char b;
    st >> b;
    REQUIRE(b == 0x7f);

    st >> b;
    REQUIRE(b == 0x45);

    st.seekg(0);
    REQUIRE(st);
  }

  SECTION("write test") {
    st << "hello";
    REQUIRE(st);

    st.seekg(0);
    REQUIRE(st);

    //this overflows the buffer and kills the stream state
    for(int i=0; i!=100; ++i) 
      st << i;
    REQUIRE( !st );
  }
}
