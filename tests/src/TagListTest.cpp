#include <cppunit/extensions/HelperMacros.h>
#include <src/TagList.hpp>
#include <iostream>
#include <sstream>

using DKIM::TagList;
using DKIM::TagListEntry;

class TagListTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( TagListTest );
	CPPUNIT_TEST( ParseTest );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void ParseTest()
	{
		TagList myTag;	
		TagListEntry myEntry;

		myTag.Reset();
		CPPUNIT_ASSERT_THROW ( myTag.Parse("v"), std::runtime_error );

		myTag.Reset();
		CPPUNIT_ASSERT_THROW ( myTag.Parse("v=1;x"), std::runtime_error );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("v=1;\r\nk=1;") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("v=1; \r\nk=1;") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("v=1;\t\nk=1;") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("\r\n") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("v=1;x=2") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("v=") );

		myTag.Reset();
		CPPUNIT_ASSERT_NO_THROW ( myTag.Parse("v=;x=   ;z  = \r\n  m ;y  = \r\n ;") );

		CPPUNIT_ASSERT ( myTag.GetTag("v", myEntry) );
		CPPUNIT_ASSERT ( myEntry.GetValue().empty() );
		CPPUNIT_ASSERT ( myTag.GetTag("x", myEntry) );
		CPPUNIT_ASSERT ( myEntry.GetValue().empty() );
		CPPUNIT_ASSERT ( myTag.GetTag("z", myEntry) );
		CPPUNIT_ASSERT ( myEntry.GetValue() == "m" );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( TagListTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( TagListTest, "TagListTest" );
