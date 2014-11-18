#include <cppunit/extensions/HelperMacros.h>
#include <src/Tokenizer.hpp>

using namespace DKIM::Tokenizer;

class TokenizerTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( TokenizerTest );
	CPPUNIT_TEST( testReadWhiteSpace );
	CPPUNIT_TEST( testValueList );
	CPPUNIT_TEST( testAddressList );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void testReadWhiteSpace()
	{
		{
			std::stringstream input(" H\t");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_WSP) == " " );
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_WSP) == "" );
			CPPUNIT_ASSERT( input.get() == 'H' );
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_WSP) == "\t" );
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_WSP) == "" );
			CPPUNIT_ASSERT( input.get() == EOF );
		}
		{
			std::stringstream input("");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_WSP) == "" );
			CPPUNIT_ASSERT( input.get() == EOF );
		}
		{
			std::stringstream input("");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_FWS) == "" );
			CPPUNIT_ASSERT( input.get() == EOF );
		}
		{
			std::stringstream input("\r\n ");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_FWS) == "\r\n " );
			CPPUNIT_ASSERT( input.get() == EOF );
		}
		{
			std::stringstream input(" \r\n ");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_FWS) == " \r\n " );
			CPPUNIT_ASSERT( input.get() == EOF );
		}
		{
			std::stringstream input(" \r\n \r\n ");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_FWS) == " \r\n ");
			CPPUNIT_ASSERT( ReadWhiteSpace(input, ::READ_FWS) == "\r\n " );
			CPPUNIT_ASSERT( input.get() == EOF );
		}
		{
			std::stringstream input(" \r\n\r\n ");
			CPPUNIT_ASSERT ( ReadWhiteSpace(input, ::READ_FWS) == "" );
		}
		{
			std::stringstream input("\r");
			CPPUNIT_ASSERT_THROW ( ReadWhiteSpace(input, ::READ_FWS), std::runtime_error );
		}
		{
			std::stringstream input(" \n");
			CPPUNIT_ASSERT ( ReadWhiteSpace(input, ::READ_FWS) == " " );
		}
		{
			std::stringstream input("\n");
			CPPUNIT_ASSERT ( ReadWhiteSpace(input, ::READ_FWS) == "" );
		}
		{
			std::stringstream input("\r\n \r");
			CPPUNIT_ASSERT ( ReadWhiteSpace(input, ::READ_FWS) == "\r\n " );
			CPPUNIT_ASSERT_THROW ( ReadWhiteSpace(input, ::READ_FWS), std::runtime_error );
		}
	}
	void testValueList()
	{
		std::list<std::string> result;

		CPPUNIT_ASSERT ( ValueList("").size() == 0 );
		CPPUNIT_ASSERT ( ValueList("a").size() == 1 );
		CPPUNIT_ASSERT ( ValueList("a:b").size() == 2 );
		CPPUNIT_ASSERT_THROW ( ValueList(":"), std::runtime_error );
		CPPUNIT_ASSERT ( ValueList("a:").size() == 1 );

		result.clear();
		CPPUNIT_ASSERT_NO_THROW ( result = ValueList(" a : b : a b : a b:b") );
		CPPUNIT_ASSERT ( result.size() == 5 );
		CPPUNIT_ASSERT ( *(result.begin()) == "a" );
		result.pop_front();
		CPPUNIT_ASSERT ( *(result.begin()) == "b" );
		result.pop_front();
		CPPUNIT_ASSERT ( *(result.begin()) == "a b" );
		result.pop_front();
		CPPUNIT_ASSERT ( *(result.begin()) == "a b" );
		result.pop_front();
		CPPUNIT_ASSERT ( *(result.begin()) == "b" );
		result.pop_front();
	}
	void testAddressList()
	{
		std::string mail;
		std::list<std::string> list;

		mail = "\"Donald \\\"d-man\\\" Duck\"<root@halon.se>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 1 );
		CPPUNIT_ASSERT ( (*list.begin()) == "root@halon.se" );

		mail = "Pete(A wonderful \\) chap) <pete(his account)@silly.test(his host)>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 1 );
		CPPUNIT_ASSERT ( (*list.begin()) == "pete@silly.test" );

		mail = "Mary Smith <mary@x.test>, jdoe@example.org, Who? <one@y.test>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 3 );
		CPPUNIT_ASSERT ( (*list.begin()) == "mary@x.test" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "jdoe@example.org" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "one@y.test" );

		mail = "\"Mary Smith <mary@x.test>\", jdoe@example.org, Who? <one@y.test>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 3 );
		CPPUNIT_ASSERT ( (*list.begin()) == "mary@x.test" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "jdoe@example.org" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "one@y.test" );

		mail = "\"<mary@x.test>\", \"jdoe@example.org\", Who? <one@y.test>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 3 );
		CPPUNIT_ASSERT ( (*list.begin()) == "mary@x.test" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "jdoe@example.org" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "one@y.test" );

		mail = "John Doe <jdoe@machine(comment).  example>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 1 );
		CPPUNIT_ASSERT ( (*list.begin()) == "jdoe@machine.example" );

		mail = "User, Company Inc <foo@example.org>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 1 );
		CPPUNIT_ASSERT ( (*list.begin()) == "foo@example.org" );

		mail = "User, Company Inc <foo@example.org>, <bar@example.org>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 2 );
		CPPUNIT_ASSERT ( (*list.begin()) == "foo@example.org" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "bar@example.org" );

		mail = "Pete(A \\\\wonderful \\) chap) <pete(his account)@silly.test(his host)>";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 1 );
		CPPUNIT_ASSERT ( (*list.begin()) == "pete@silly.test" );

		mail = "A Group(Some people)\r\n :Chris Jones <c@(Chris's host.)public.example>,\r\n" \
				" joe@example.org,\r\n John <jdoe@one.test> (my dear friend); (the end of the group)";
		CPPUNIT_ASSERT ( (list = ParseAddressList(mail)).size() == 3 );
		CPPUNIT_ASSERT ( (*list.begin()) == "c@public.example" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "joe@example.org" );
		list.pop_front();
		CPPUNIT_ASSERT ( (*list.begin()) == "jdoe@one.test" );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( TokenizerTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( TokenizerTest, "TokenizerTest" );
