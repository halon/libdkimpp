#include <cppunit/extensions/HelperMacros.h>
#include <src/Base64.hpp>

using DKIM::Conversion::Base64_Encode;
using DKIM::Conversion::Base64_Decode;

class Base64Test : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( Base64Test );
	CPPUNIT_TEST( ConversionTest );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void ConversionTest()
	{
		std::string d = "Hello World? Is it mine to take over? I would so if I ever got the chance :)";
		std::string e = "SGVsbG8gV29ybGQ/IElzIGl0IG1pbmUgdG8gdGFrZSBvdmVyPyBJIHdvdWxkIHNvIGlmIEkgZXZlciBnb3QgdGhlIGNoYW5jZSA6KQ==";
		CPPUNIT_ASSERT ( Base64_Encode(d) == e );
		CPPUNIT_ASSERT ( Base64_Decode(e) == d );
		CPPUNIT_ASSERT ( Base64_Decode(Base64_Encode("Hej")) == "Hej" );
		CPPUNIT_ASSERT ( Base64_Decode(Base64_Encode("")) == "" );
		CPPUNIT_ASSERT ( Base64_Decode(Base64_Encode("\x12\x22")) == "\x12\x22" );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( Base64Test );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( Base64Test, "Base64Test" );
