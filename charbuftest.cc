#include "catch.hpp"
#include "charstream.h"

using namespace std;

TEST_CASE("Charbuf works for basic ops", "[charstream]") {
  uint8_t s[]{0x7f, 0x45, 0x4c, 0x46, 0x02, 0x01, 0x01, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};

  charstream st((char*)s, sizeof(s));

  SECTION("read test") {
    char b;
    st >> b;
    REQUIRE(b == 0x7f);

    st >> b;
    REQUIRE(b == 0x45);

    st.seekg(0);
    REQUIRE(st);
  }

  SECTION("read/write/seek test") {
    char b;

    REQUIRE(st << "hello");
    REQUIRE( ((st >> b) && b == 'h') );
    REQUIRE( ((st >> b) && b == 'e') );
    REQUIRE( ((st >> b) && b == 'l') );

    //mixing write shouldn't throw off read
    st.seekp(-3, ios_base::end);
    REQUIRE(st << "end");

    REQUIRE( ((st >> b) && b == 'l') );
    REQUIRE( ((st >> b) && b == 'o') );

    st.seekp(3, ios_base::beg);
    REQUIRE(st << "per");

    st.seekg(-4, ios_base::cur);
    REQUIRE( ((st >> b) && b == 'e') );
    REQUIRE( ((st >> b) && b == 'l') );
    REQUIRE( ((st >> b) && b == 'p') );
    REQUIRE( ((st >> b) && b == 'e') );
    REQUIRE( ((st >> b) && b == 'r') );

    st.seekg(-3, ios_base::end);
    REQUIRE( ((st >> b) && b == 'e') );
    REQUIRE( ((st >> b) && b == 'n') );
    REQUIRE( ((st >> b) && b == 'd') );
  }

  SECTION("overflow test") {
    for (int i = 0; i != 100; ++i)
      st << i;
    REQUIRE(!st);
  }

  SECTION("underflow test") {
    char b;
    for (int i = 0; i != 100; ++i)
      st >> b;
    REQUIRE(!st);
  }
}
