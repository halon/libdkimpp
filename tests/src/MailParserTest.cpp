#include <cppunit/extensions/HelperMacros.h>
#include <src/MailParser.hpp>
#include <iostream>
#include <sstream>

using DKIM::Message;

class MailParserTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( MailParserTest );
	CPPUNIT_TEST( ParserTest );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void ParserTest()
	{
		Message myMessage;

		{
			std::stringstream data("Subject: test");
			myMessage.Reset();
			while(myMessage.ParseLine(data) && !myMessage.IsDone()) { }
			Message::HeaderList::const_iterator i = myMessage.GetHeaders().begin();

			CPPUNIT_ASSERT( myMessage.GetHeaders().size() == 1 );
			CPPUNIT_ASSERT( (*i)->GetName() == "Subject" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "Subject: test" );

			CPPUNIT_ASSERT( myMessage.GetBodyOffset() == -1 );
		}

		{
			std::stringstream data("Subject: test\r\n");
			myMessage.Reset();
			while(myMessage.ParseLine(data) && !myMessage.IsDone()) { }
			Message::HeaderList::const_iterator i = myMessage.GetHeaders().begin();

			CPPUNIT_ASSERT( myMessage.GetHeaders().size() == 1 );
			CPPUNIT_ASSERT( (*i)->GetName() == "Subject" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "Subject: test" );

			CPPUNIT_ASSERT( myMessage.GetBodyOffset() == -1 );
		}

		{
			std::stringstream data("test\r\n");
			myMessage.Reset();
			while(myMessage.ParseLine(data) && !myMessage.IsDone()) { }
			Message::HeaderList::const_iterator i = myMessage.GetHeaders().begin();

			CPPUNIT_ASSERT( myMessage.GetHeaders().size() == 1 );
			CPPUNIT_ASSERT( (*i)->GetName() == "" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "test" );
		}

		{
			std::stringstream data("Subject: test\r\n\r\n");
			myMessage.Reset();
			while(myMessage.ParseLine(data) && !myMessage.IsDone()) { }
			Message::HeaderList::const_iterator i = myMessage.GetHeaders().begin();

			CPPUNIT_ASSERT( myMessage.GetHeaders().size() == 1 );
			CPPUNIT_ASSERT( (*i)->GetName() == "Subject" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "Subject: test" );

			CPPUNIT_ASSERT( myMessage.GetBodyOffset() == 17 );
		}

		{
			std::stringstream data("Subject: test\r\nSubject2 : test\r\nSubject3 : test\r\n test\r\nxxx");
			myMessage.Reset();
			while(myMessage.ParseLine(data) && !myMessage.IsDone()) { }
			Message::HeaderList::const_iterator i = myMessage.GetHeaders().begin();

			CPPUNIT_ASSERT( myMessage.GetHeaders().size() == 4 );
			CPPUNIT_ASSERT( (*i)->GetName() == "Subject" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "Subject: test" );
			i++;
			CPPUNIT_ASSERT( (*i)->GetName() == "Subject2" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "Subject2 : test" );
			i++;
			CPPUNIT_ASSERT( (*i)->GetName() == "Subject3" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "Subject3 : test\r\n test" );
			i++;
			CPPUNIT_ASSERT( (*i)->GetName() == "" );
			CPPUNIT_ASSERT( (*i)->GetHeader() == "xxx" );
		}
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( MailParserTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( MailParserTest, "MailParserTest"  );
