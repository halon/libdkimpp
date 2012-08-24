#include <cppunit/extensions/HelperMacros.h>
#include <src/Canonicalization.hpp>

using DKIM::Conversion::CanonicalizationHeader;
using DKIM::Conversion::CanonicalizationBody;

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
		std::vector<std::string> output;
		CanonicalizationBody canonicalbody ( DKIM::DKIM_C_SIMPLE );

		/*
		 * truncation of empty lines at the end of a message
		 */

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("Hello ", output) == 1 &&
					output[0] == "Hello "
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("\tWorld", output) == 4 &&
					output[0] == "\r\n" &&
					output[1] == "\r\n" &&
					output[2] == "\r\n" &&
					output[3] == "\tWorld"
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.Done(output) == 1 &&
					output[0] == "\r\n"
				);

		canonicalbody.Reset();

		/*
		 * empty body should return \r\n
		 */

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.Done(output) == 1 &&
					output[0] == "\r\n"
				);

	}
	void TestBodyRelaxed()
	{
		std::vector<std::string> output;
		CanonicalizationBody canonicalbody ( DKIM::DKIM_C_RELAXED );

		/*
		 * truncation of empty lines at the end of a message
		 */

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("Hello ", output) == 1 &&
					output[0] == "Hello"
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("\tWorld\t\t!", output) == 4 &&
					output[0] == "\r\n" &&
					output[1] == "\r\n" &&
					output[2] == "\r\n" &&
					output[3] == " World !"
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("       ", output) == 0
				);
		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.Done(output) == 1 &&
					output[0] == "\r\n"
				);

		canonicalbody.Reset();

		/*
		 * remove all wsp at the end of a line
		 */

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("Hello ", output) == 1 &&
					output[0] == "Hello"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine("Hello \t  ", output) == 2 &&
					output[0] == "\r\n" &&
					output[1] == "Hello"
				);

		/*
		 * merge multiple wsp
		 */

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine(" \t Hello \t  ", output) == 2 &&
					output[0] == "\r\n" &&
					output[1] == " Hello"
				);

		output.clear();
		CPPUNIT_ASSERT (
					canonicalbody.FilterLine(" \t Hello \tWorld \t  ", output) == 2 &&
					output[0] == "\r\n" &&
					output[1] == " Hello World"
				);
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( CanonicalizationTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( CanonicalizationTest, "CanonicalizationTest" );
