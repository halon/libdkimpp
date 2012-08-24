#include <cppunit/extensions/HelperMacros.h>
#include <src/Signatory.hpp>
#include <src/Validatory.hpp>
#include <iostream>
#include <sstream>

#include "Keys.hpp"

using DKIM::Signatory;
using DKIM::SignatoryOptions;
using DKIM::Validatory;

class SignatoryTest : public CppUnit::TestFixture {
	CPPUNIT_TEST_SUITE( SignatoryTest );
	CPPUNIT_TEST( SignTest );
	CPPUNIT_TEST_SUITE_END();
	public:
	void setUp() { }
	void tearDown() { }
	void SignTest()
	{
		{
			SignatoryOptions options;
			options.SetPrivateKey(DKIM_PRIVATEKEY).SetDomain("halon.se").SetSelector("dkim-test");
			_SignMailTest(options, "From: erik@halon.se\r\n\r\nThis is my first DKIM test");
			_SignMailTest(options, "From: erik@halon.se\r\n\r\n");
			_SignMailTest(options, "From: erik@halon.se\r\n");
			_SignMailTest(options, "From: erik@halon.se");
		}
		{
			SignatoryOptions options;
			options.SetPrivateKey(DKIM_PRIVATEKEY).SetDomain("halon.se").SetSelector("dkim-test");
			options.SetSignBodyLength(0);
			_SignMailTest(options, "From: erik@halon.se\r\n\r\n");
			_SignMailTest(options, "From: erik@halon.se\r\n");
			_SignMailTest(options, "From: erik@halon.se");
			_SignMailTest(options, "From: erik@halon.se\r\n\r\n123");
			_SignMailTest(options, "From: erik@halon.se\r\n");
			_SignMailTest(options, "From: erik@halon.se");
		}	
	}
	void _SignMailTest(const SignatoryOptions& options, const std::string& mail)
	{
		std::string head;
		std::stringstream fp;
		std::stringstream fp2;
		std::string DKIMPublicKey = "v=DKIM1; p=" DKIM_PUBLICKEY "; t=s";

		fp.str(mail);
		CPPUNIT_ASSERT_NO_THROW ( head = Signatory(fp).CreateSignature(options) );

		fp2.str(head + "\r\n" + mail);
		Validatory myValidatory(fp2);

		const Validatory::SignatureList& siglist = myValidatory.GetSignatures();
		CPPUNIT_ASSERT ( siglist.size() == 1 );

		DKIM::Signature sig;
		CPPUNIT_ASSERT_NO_THROW ( myValidatory.GetSignature(siglist.begin(), sig) );

		DKIM::PublicKey pub;
		CPPUNIT_ASSERT_NO_THROW ( pub.Parse(DKIMPublicKey) );
		CPPUNIT_ASSERT_NO_THROW ( myValidatory.CheckSignature(siglist.begin(), sig, pub) );
	}
};

CPPUNIT_TEST_SUITE_REGISTRATION( SignatoryTest );
CPPUNIT_TEST_SUITE_NAMED_REGISTRATION( SignatoryTest, "SignatoryTest" );
