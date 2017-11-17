#include <cppunit/extensions/HelperMacros.h>
#include <src/Canonicalization.hpp>

using DKIM::Conversion::CanonicalizationHeader;
using DKIM::Conversion::CanonicalizationBody;

struct StringTest
{
	std::string str;
	void update(const char* ptr, size_t i)
	{
		str.append(ptr, i);
	}
};

std::string CanonicalizationBodyTest(std::string input, DKIM::CanonMode type)
{
	std::stringstream str(input);
	StringTest foo;
	CanonicalizationBody(str, type, 0, false, 0, std::bind(&StringTest::update, &foo, std::placeholders::_1, std::placeholders::_2));
	return foo.str;
}

class CanonicalizationTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( CanonicalizationTest );
	CPPUNIT_TEST( TestHeaderSimple );
	CPPUNIT_TEST( TestHeaderRelaxed );
	CPPUNIT_TEST( TestBodySimple );
	CPPUNIT_TEST( TestBodyRelaxed );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void TestHeaderSimple()
	{
		std::vector<std::string> output;
		CanonicalizationHeader canonicalhead ( DKIM::DKIM_C_SIMPLE );

		/*
		 * this type does not require alter the header
		 */

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("This should not be modified") == "This should not be modified"
				);

	}
	void TestHeaderRelaxed()
	{
		std::vector<std::string> output;
		CanonicalizationHeader canonicalhead ( DKIM::DKIM_C_RELAXED );

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("SUBJect: AbC") == "subject:AbC"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("SUBJect\t : AbC") == "subject:AbC"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("SUBJect:\r\n AbC") == "subject:AbC"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("SUBJect: AbC\r\n\t hej") == "subject:AbC hej"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("SUBJect: AbC\r\n\t hej") == "subject:AbC hej"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalhead.FilterHeader("SUBJect: AbC\r\n\t hej\r\n      \thej\t") == "subject:AbC hej hej"
				);

	}
	void TestBodySimple()
	{
		/*
		 * truncation of empty lines at the end of a message
		 */

		CPPUNIT_ASSERT (
					CanonicalizationBodyTest("Hello \r\n\r\n\r\n\tWorld\r\n\r\n", DKIM::DKIM_C_SIMPLE) ==
					"Hello \r\n\r\n\r\n\tWorld\r\n"
				);

		/*
		 * empty body should return \r\n
		 */

		CPPUNIT_ASSERT (
					CanonicalizationBodyTest("", DKIM::DKIM_C_SIMPLE) ==
					"\r\n"
				);
	}
	void TestBodyRelaxed()
	{
		/*
		 * truncation of empty lines at the end of a message
		 */

		/*
		 * remove all wsp at the end of a line
		 */

		/*
		 * merge multiple wsp
		 */

		CPPUNIT_ASSERT (
					CanonicalizationBodyTest("Hello \r\n\r\n\r\n\tWorld\t\t!\r\n\r\n\r\n       \r\nHello \r\nHello \t  \r\n \t Hello \t  \r\n \t Hello \tWorld \t  \r\n", DKIM::DKIM_C_RELAXED) ==
					"Hello\r\n\r\n\r\n World !\r\n\r\n\r\n\r\nHello\r\nHello\r\n Hello\r\n Hello World\r\n"
				);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( CanonicalizationTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( CanonicalizationTest, "CanonicalizationTest" );
