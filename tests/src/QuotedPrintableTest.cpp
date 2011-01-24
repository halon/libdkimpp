#include <cppunit/extensions/HelperMacros.h>
#include <src/QuotedPrintable.hpp>

using DKIM::Conversion::QuotedPrintable;

class QuotedPrintableTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( QuotedPrintableTest );
	CPPUNIT_TEST( DecodeTest );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void DecodeTest()
	{
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("=41") == "A" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("=20") == " " );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("\r\n ") == "" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("=41 =42") == "AB" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("=41 \r\n  =42") == "AB" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("=41 \r\n  =42 \r\n  ") == "AB" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode("<") == "<" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode(">") == ">" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode(":") == ":" );
		CPPUNIT_ASSERT ( QuotedPrintable::Decode(" ") == "" );

		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("=") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("=a") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("=a0") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("=a0") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("=g0") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("\r") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("\t \r") , std::runtime_error );
		CPPUNIT_ASSERT_THROW ( QuotedPrintable::Decode("\n") , std::runtime_error );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( QuotedPrintableTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( QuotedPrintableTest, "QuotedPrintableTest"  );
