#include <cppunit/extensions/HelperMacros.h>
#include <src/Util.hpp>

using DKIM::Util::MatchWithWildCard;

class UtilTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( UtilTest );
	CPPUNIT_TEST( MatchWithWildCardTest );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void MatchWithWildCardTest()
	{
		CPPUNIT_ASSERT( MatchWithWildCard("*", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("erik*", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("*erik", "erik") );
		CPPUNIT_ASSERT( ! MatchWithWildCard("*erik*", "erik") );
		CPPUNIT_ASSERT( ! MatchWithWildCard("**", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("*rik", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("e*ik", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("er*ik", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("*ik", "erik") );
		CPPUNIT_ASSERT( ! MatchWithWildCard("f*ik", "erik") );
		CPPUNIT_ASSERT( MatchWithWildCard("*", "") );
		CPPUNIT_ASSERT( MatchWithWildCard("*", "*") );
		CPPUNIT_ASSERT( MatchWithWildCard("**", "*") );
		CPPUNIT_ASSERT( ! MatchWithWildCard("", "erik") );
		CPPUNIT_ASSERT( ! MatchWithWildCard("", "e") );
		CPPUNIT_ASSERT( ! MatchWithWildCard("", "") );
		CPPUNIT_ASSERT( MatchWithWildCard("*-offer", "test-offer") );
		CPPUNIT_ASSERT( MatchWithWildCard("*-offer", "-offer") );
		CPPUNIT_ASSERT( MatchWithWildCard("user+*", "user+") );
		CPPUNIT_ASSERT( MatchWithWildCard("user+*", "user+test") );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( UtilTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( UtilTest, "UtilTest"  );
