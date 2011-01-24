#include <cppunit/extensions/HelperMacros.h>
#include <src/EncodedWord.hpp>

using DKIM::Conversion::EncodedWord;

class EncodedWordTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( EncodedWordTest );
	CPPUNIT_TEST( testEncodedWord );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void testEncodedWord()
	{
		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?q?=20?=") == " " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?=") == " " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?= ") == " " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?= =?8859-1?q?=20?=") == "  " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?=  =?8859-1?q?=20?=") == "  " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?= A") == "  A" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?=  =?8859-1?q?_?=  =?8859-1?Q?=20?=") == "   " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?8859-1?Q?=20?=  A  A  =?8859-1?Q?=20?=") == "   A  A " );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?= =?ISO-8859-2?Q?_b?=") == "a b" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a_b?=") == "a b" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?=\r\n   =?ISO-8859-1?Q?b?=") == "ab" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?=") == "a" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?= b") == "a b" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?= =?ISO-8859-1?Q?b?=") == "ab" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?b?=") == "ab" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a_b?=") == "a b" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?Q?a?=  =?ISO-8859-1?Q?_b?=") == "a b" );

		CPPUNIT_ASSERT ( EncodedWord::Decode("=?ISO-8859-1?-?a?=") == "=?ISO-8859-1?-?a?=" );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( EncodedWordTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( EncodedWordTest, "EncodedWordTest"  );
