#include "Validatory.hpp"

using DKIM::Validatory;
using DKIM::ADSP;

#include "Signatory.hpp"

using DKIM::Signatory;
using DKIM::SignatoryOptions;

#include <string.h>

#include <getopt.h>

#include "Resolver.hpp"

bool MyResolver(const std::string& domain, std::string& result, void* data)
{
	return DKIM::Util::Resolver().GetTXT(domain, result);
}

extern char *__progname;

void usage(FILE* fp, int status)
{
	fprintf(fp,
			"\n"
			" libdkimtest build on " __DATE__ " (c) Halon Security <support@halon.se>\n"
			"\n"
			" %s [ options ] file.eml\n"
			"\n"
			" Options\n"
			"\n"
			" -h,  --help       Show this help\n"
			" -v,  --validate   Validate Only\n"
			"\n"
			" Signatory options (default)\n"
			"\n"
			" -s,  --selector   <selector>\n"
			" -d,  --domain     <fqdn>\n"
			" -k,  --keyfile    <file>\n"
			"\n"
			" Examples\n"
			"\n"
			" %s -s garfield -d halon.se \\\n        -k keystore/private.pem message.eml"
			"\n"
			" %s -v message.eml"
			"\n"
			"\n"
			, __progname, __progname, __progname
			);
	exit(status);
}

int main(int argc, char* argv[])
{
	__progname = argv[0];

	bool validate = false;
	std::string selector;
	std::string domain;
	std::string keyfile;
	Validatory::ValidatorType type = Validatory::DKIM;
	unsigned long arcInstance = 0;

	// no arguments
	if (argc < 2)
		usage(stderr, 2);

	// longopts
	static struct option longopts[] = {
		{ "arc",	 	no_argument,		NULL,		'a'	},
		{ "arcinstance",no_argument,		NULL,		'A'	},
		{ "help",		no_argument,		NULL,		'h'	},
		{ "validate",	no_argument,		NULL,		'v'	},
		{ "selector",	required_argument,	NULL,		's'	},
		{ "domain",		required_argument,	NULL,		'd'	},
		{ "keyfile",	required_argument,	NULL,		'k'	},
		{ NULL,			0,					NULL,		0	}
	};

	// fetching arguments..
	opterr = 0;
	optind = 0;
	int ch;
	while ((ch = getopt_long(argc, argv, "aA:hvs:d:k:", longopts, NULL)) != -1) {
		switch (ch)
		{
			case 'a':
				type = Validatory::ARC;
				break;
			case 'A':
				arcInstance = strtoul(optarg, nullptr, 10);
				break;
			case 'v':
				validate = true;
				break;
			case 'h':
				usage(stdout, 0);
				break;
			case 's':
				selector = optarg;
				break;
			case 'd':
				domain = optarg;
				break;
			case 'k':
				keyfile = optarg;
				break;
			case 0:
				break;
			default:
				usage(stderr, 2);
				break;
		}
	}
	argc -= optind;
	argv += optind;

	if (argc < 1)
		usage(stderr, 2);

	if (!validate && (selector.empty() || domain.empty() || keyfile.empty()))
		usage(stderr, 2);

	//  sign the message..
	if (!validate)
	{
		// readkey
		std::ifstream kfp(keyfile);
		if (!kfp) {
			fprintf(stderr, "keyfile %s could not be open\n", keyfile.c_str());
			return 1;
		}
		std::string key((std::istreambuf_iterator<char>(kfp)),
				std::istreambuf_iterator<char>());

		std::ifstream fp(argv[0]);
		try {
			printf("%s\r\n",
					Signatory(fp).CreateSignature(
						SignatoryOptions()
						.SetPrivateKey(key)
						.SetDomain(domain)
						.SetSelector(selector)
						.SetARCInstance(arcInstance)
						.SetCanonModeHeader(DKIM::DKIM_C_RELAXED)
						.SetCanonModeBody(DKIM::DKIM_C_RELAXED)
						).c_str() );
		} catch (std::runtime_error& e) {
			fprintf(stderr, "%s\n", e.what());
			return 1;
		}

		return 0;
	}

	// validate messages (0 .. argv)
	for (int x = 0; x < argc; x++)
	{
		std::ifstream fp(argv[x]);
		Validatory mail(fp, type);

		mail.CustomDNSResolver = MyResolver;

		// first check ADSP status
		try {
			std::list<ADSP> adsp;
			mail.GetADSP(adsp);
			for (std::list<ADSP>::const_iterator i = adsp.begin(); i != adsp.end(); ++i)
			{
				printf("[%s][ADSP][%s] %s/%s\n", argv[x], i->GetDomain().c_str(), i->GetResultAsString().c_str(), i->GetReason().c_str());
			}
		} catch (DKIM::TemporaryError& e) {
			printf("[%s][ADSP] TEMPERR:%s\n", argv[x], e.what());
		} catch (DKIM::PermanentError& e) {
			printf("[%s][ADSP] PERMERR:%s\n", argv[x], e.what());
		}

		// then list all valid SDID's
		for (Validatory::SignatureList::const_iterator i = mail.GetSignatures().begin();
				i != mail.GetSignatures().end(); ++i)
		{
			DKIM::PublicKey pub;
			DKIM::Signature sig;
			try {
				mail.GetSignature(i, sig);
				mail.GetPublicKey(sig, pub);
				mail.CheckSignature(*i, sig, pub);
				printf("[%s][%s] OK\n", argv[x], sig.GetDomain().c_str());
			} catch (DKIM::TemporaryError& e) {
				printf("[%s][%s] TEMPERR:%s\n", argv[x], sig.GetDomain().c_str(), e.what());
			} catch (DKIM::PermanentError& e) {
				if (pub.SoftFail())
					printf("[%s][%s] SOFT:%s\n", argv[x], sig.GetDomain().c_str(), e.what());
				else
					printf("[%s][%s] = %s\n", argv[x], sig.GetDomain().c_str(), e.what());
			}
		}
	}

	return 0;
}
