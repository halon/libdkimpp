/*
 *
 * Copyright (C) 2009-2014 Halon Security <support@halon.se>
 *
 * This file is part of libdkim++.
 *
 * libdkim++ is free software: you can redistribute it and/or modify
 * it under the terms of the GNU Lesser General Public License as published by
 * the Free Software Foundation, either version 3 of the License, or
 * (at your option) any later version.
 *
 * libdkim++ is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU Lesser General Public License for more details.
 * 
 * You should have received a copy of the GNU Lesser General Public License
 * along with libdkim++.  If not, see <http://www.gnu.org/licenses/>.
 *
 */
#include "Validatory.hpp"

using DKIM::Validatory;

#include "Canonicalization.hpp"
#include "Util.hpp"
#include "Resolver.hpp"
#include "TagList.hpp"
#include "EncodedWord.hpp"
#include "Tokenizer.hpp"

using DKIM::Conversion::CanonicalizationHeader;
using DKIM::Conversion::CanonicalizationBody;
using DKIM::Util::StringFormat;
using DKIM::TagList;
using DKIM::TagListEntry;

#include <algorithm>
#include <sstream>
#include <memory.h>

//#define DEBUG

Validatory::Validatory(std::istream& stream, bool doubleDots)
: CustomDNSResolver(NULL), CustomDNSData(NULL), m_file(stream) , m_doubleDots(doubleDots)
{
	EVP_MD_CTX_init( &m_ctx_head );
	EVP_MD_CTX_init( &m_ctx_body );

	while (m_msg.ParseLine(m_file, doubleDots) && !m_msg.IsDone()) { }

	DKIM::Message::HeaderList::const_iterator i;
	for (i = m_msg.GetHeaders().begin(); i != m_msg.GetHeaders().end(); ++i)
	{
		// headers should be matched in lower-case
		std::string headerName = (*i)->GetName();
		transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);

		// collect all dkim-signatures
		if (headerName == "dkim-signature")
			m_dkimHeaders.push_back(*i);
	}
}

Validatory::~Validatory()
{
	EVP_MD_CTX_cleanup( &m_ctx_head );
	EVP_MD_CTX_cleanup( &m_ctx_body );
}

/*
 * GetSignature()
 *
 * Get the signature from supported header iterator
 */
void Validatory::GetSignature(const Message::HeaderList::const_iterator& headerIter,
		DKIM::Signature& sig)	
	throw (DKIM::PermanentError)
{
	sig.Parse((*headerIter)->GetHeader().substr((*headerIter)->GetValueOffset()));

	// create signature for our body (message data)
	switch (sig.GetAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_DigestInit( &m_ctx_body, EVP_sha1() );
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_DigestInit( &m_ctx_body, EVP_sha256() );
			break;
	}

	CanonicalizationBody canonicalbody ( sig.GetCanonModeBody() );

	// if we should limit the size of the body we hash
	bool limitBody = sig.GetBodySizeLimit();
	size_t bodySize = sig.GetBodySize();

	// if we have a message: seek to GetBodyOffset()
	if (m_msg.GetBodyOffset() != -1)
	{
		m_file.clear();
		m_file.seekg(m_msg.GetBodyOffset(), std::istream::beg);

		std::string s;
		while (std::getline(m_file, s) || m_file.peek() != EOF)
		{
			// double dots (postfix file may have .., instead of .)
			if (m_doubleDots && s.substr(0, 2) == "..")
			{
				s.erase(0, 1);
			}

			// remove possible \r (if not removed by getline *probably not*)
			if (s.size() > 0 && s[s.size()-1] == '\r')
				s.erase(s.size()-1);

			// canonical body
			std::vector<std::string> output;
			if (canonicalbody.FilterLine(s, output))
			{
				for (std::vector<std::string>::const_iterator i = output.begin();
						i != output.end(); ++i)
				{
					if (limitBody && bodySize == 0) break;
#ifdef DEBUG
					if (*i == "\r\n") printf("[CRLF]\n");
					else printf("[%s]\n", i->c_str());
#endif
					EVP_DigestUpdate(&m_ctx_body, i->c_str(),
							limitBody?std::min(i->size(), bodySize):i->size());
					bodySize -= std::min(i->size(), bodySize);
				}
			}
		}
	}

	// else call (Done) -- which may insert a last CRLF if the body was empty
	if (m_msg.GetBodyOffset() != -1 || m_file.peek() == EOF)
	{
		std::vector<std::string> output;
		if (canonicalbody.Done(output))
		{
			for (std::vector<std::string>::const_iterator i = output.begin();
					i != output.end(); ++i)
			{
				if (limitBody && bodySize == 0) break;
#ifdef DEBUG
				if (*i == "\r\n") printf("[CRLF]\n");
				else printf("[%s]\n", i->c_str());
#endif
				EVP_DigestUpdate(&m_ctx_body, i->c_str(),
						limitBody?std::min(i->size(), bodySize):i->size());
				bodySize -= std::min(i->size(), bodySize);
			}
		}
	}

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_DigestFinal_ex(&m_ctx_body, md_value, &md_len);
	EVP_MD_CTX_cleanup( &m_ctx_body );

	if (sig.GetBodyHash().size() != md_len ||
			memcmp(sig.GetBodyHash().c_str(), md_value, md_len) != 0)
	{
		throw DKIM::PermanentError("Body hash did not verify");
	}
}

/*
 * GetPublicKey()
 *
 * Get the publickey from supported sources (ie. dns/txt)
 */
void Validatory::GetPublicKey(const DKIM::Signature& sig,
		DKIM::PublicKey& pubkey)
	throw (DKIM::PermanentError, DKIM::TemporaryError)
{
	if (sig.GetQueryType() == DKIM::Signature::DKIM_Q_DNSTXT)
	{
		std::string query = sig.GetSelector() + "._domainkey." + sig.GetDomain();
		std::string publicKey;

		if ((CustomDNSResolver?
					CustomDNSResolver(query, publicKey, CustomDNSData):
					DKIM::Util::Resolver().GetTXT(query, publicKey)
			))
		{
			if (publicKey.empty())
				throw DKIM::PermanentError(StringFormat("No key for signature %s._domainkey.%s",
							sig.GetSelector().c_str(),
							sig.GetDomain().c_str()
							)
						);
			pubkey.Parse(publicKey);
			return;
		}
		throw DKIM::TemporaryError(StringFormat("DNS query failed for %s._domainkey.%s",
					sig.GetSelector().c_str(),
					sig.GetDomain().c_str()
					)
				);
	}
	throw DKIM::PermanentError(StringFormat("Unsupported query type %d",
				(int)sig.GetQueryType()
				)
			);
}

/*
 * CheckSignature()
 *
 * Validate the message according to rfc4871
 */
void Validatory::CheckSignature(const Message::HeaderList::const_iterator& headerIter,
		const DKIM::Signature& sig,
		const DKIM::PublicKey& pub)
	throw (DKIM::PermanentError)
{
	// multiple signatures (must cleanup)
	EVP_MD_CTX_cleanup( &m_ctx_body );
	EVP_MD_CTX_cleanup( &m_ctx_head );

	// sanity checking (between sig and pub)
	if (pub.GetAlgorithms().size() > 0)
		if (find(pub.GetAlgorithms().begin(), pub.GetAlgorithms().end(), sig.GetAlgorithm()) == pub.GetAlgorithms().end())
			throw DKIM::PermanentError("Algorithm is not allowed");

	if (find(pub.GetFlags().begin(), pub.GetFlags().end(), "s") != pub.GetFlags().end())
		if (sig.GetDomain() != sig.GetMailDomain())
			throw DKIM::PermanentError("Domain must match sub-domain (flag s)");

	/*
	 If a DKIM verifier finds a selector record that has an empty "g" field ("g=;")
	 and it does not have a "v" field ("v=DKIM1;") at its beginning, it is faced with deciding if this record was

	 1. from a DK signer that transitioned to supporting DKIM but forgot to remove the "g"
	 	field (so that it could be used by both DK and DKIM verifiers), or
	 2. from a DKIM signer that truly meant to use the empty "g" field but forgot to put in
	 	the "v" field. It is RECOMMENDED that you treat such records using the first
		interpretation, and treat such records as if the signer did not have a "g" field in the record.
	*/

	// if we have a "g"-tag
	if (find(pub.GetFlags().begin(), pub.GetFlags().end(), "g") != pub.GetFlags().end())
	{
		// if it's empty... and we don't have a version...
		if (pub.GetMailLocalPart().empty() && find(pub.GetFlags().begin(), pub.GetFlags().end(), "v") == pub.GetFlags().end())
		{
			// do the RECOMMENDED interpretation and treat such records as if the signer did not have a "g" field in the record.
		} else
		{
			if (DKIM::Util::MatchWithWildCard(pub.GetMailLocalPart(), sig.GetMailLocalPart()) != true)
				throw DKIM::PermanentError("Unmatched local-part");
		}
	}

	// create signature for our header
	switch (sig.GetAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_VerifyInit( &m_ctx_head, EVP_sha1() );
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_VerifyInit( &m_ctx_head, EVP_sha256() );
			break;
	}

	CanonicalizationHeader canonicalhead ( sig.GetCanonModeHeader() );

	// add all headers to our cache (they will be pop of the end)
	std::map<std::string, Message::HeaderList> headerCache;
	for (Message::HeaderList::const_iterator hIter = m_msg.GetHeaders().begin();
			hIter != m_msg.GetHeaders().end();
			++hIter)
	{
		std::string headerName = (*hIter)->GetName();
		transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);
		headerCache[headerName].push_back(*hIter);
	}

	// add all signed headers to our hash
	for (std::list<std::string>::const_iterator hIter = sig.GetSignedHeaders().begin();
			hIter != sig.GetSignedHeaders().end(); ++hIter)
	{
		std::string tmp;
		std::string name = *hIter;
		transform(name.begin(), name.end(), name.begin(), tolower);

		std::map<std::string, Message::HeaderList>::iterator head = headerCache.find(name);

		// if this occurred
		// 1. we do not have a header of that name at all
		// 2. all headers with that name has been included...
		if (head == headerCache.end() || head->second.size() == 0)
			continue;	

#ifdef DEBUG
		printf("[%s]\n", canonicalhead.FilterHeader(head->second.back()->GetHeader()).c_str());
		printf("[CRLF]\n");
#endif
		tmp = canonicalhead.FilterHeader(head->second.back()->GetHeader()) + "\r\n";
		head->second.pop_back();
		EVP_VerifyUpdate(&m_ctx_head, tmp.c_str(), tmp.size());
	}

	// add our dkim-signature to the calculation (remove the "b"-tag)
	std::string h = (*headerIter)->GetHeader().substr(0, (*headerIter)->GetValueOffset());
	std::string v = (*headerIter)->GetHeader().substr((*headerIter)->GetValueOffset());

	DKIM::TagListEntry bTag;
	sig.GetTag("b", bTag);
	v.erase((int)bTag.GetValueOffset(), bTag.GetValue().size());

	std::string tmp = canonicalhead.FilterHeader(h + v);
#ifdef DEBUG
	printf("[%s]\n", tmp.c_str());
#endif
	EVP_VerifyUpdate(&m_ctx_head, tmp.c_str(), tmp.size());

	// verify the header signature
	if (EVP_VerifyFinal(&m_ctx_head,
				(const unsigned char*)sig.GetSignatureData().c_str(),
				sig.GetSignatureData().size(),
				pub.GetPublicKey()
				) != 1)
		throw DKIM::PermanentError("Signature did not verify");
	EVP_MD_CTX_cleanup( &m_ctx_head );

	// success!
}

/*
 * GetADSP()
 *
 * Get ADSP status for message rfc5617
 */
void Validatory::GetADSP(std::list<DKIM::ADSP>& adsp)
	throw (DKIM::PermanentError, DKIM::TemporaryError)
{
	/**
	 * Start by collecting all From: <> addresses (this runtime-time free...)
	 */
	std::list<std::string> senders;

	for (DKIM::Message::HeaderList::const_iterator i = m_msg.GetHeaders().begin();
		i != m_msg.GetHeaders().end(); ++i)
	{
		std::string headerName = (*i)->GetName();
		transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);

		// find from: <...> header(s)...
		if (headerName == "from")
		{
			std::string header = (*i)->GetHeader().substr((*i)->GetValueOffset());

			header = DKIM::Conversion::EncodedWord::Decode(header);

			std::list<std::string> addrlist = DKIM::Tokenizer::ParseAddressList(header);
			for (std::list<std::string>::const_iterator aIter = addrlist.begin(); aIter != addrlist.end(); ++aIter)
			{
				// if no address is claimed to follow a ADSP, try the next one
				if (aIter->empty()) continue;

				size_t atSign = aIter->rfind("@");
				if (atSign == std::string::npos)
					throw DKIM::PermanentError("Found invalid sender address: " + *aIter);

				std::string host = aIter->substr(atSign + 1);
				transform(host.begin(), host.end(), host.begin(), tolower);

				senders.push_back(host);
			}
		}
	}

	std::map<std::string, std::pair<int, std::string> > dkimResult;

	for (Validatory::SignatureList::const_iterator i = GetSignatures().begin();
			i != GetSignatures().end(); ++i)
	{
		DKIM::PublicKey pub;
		DKIM::Signature sig;
		try {
			GetSignature(i, sig);
			GetPublicKey(sig, pub);
			CheckSignature(i, sig, pub);

			dkimResult[sig.GetDomain()] = std::make_pair(1, "pass");
		} catch (DKIM::TemporaryError& e) {
			dkimResult[sig.GetDomain()] = std::make_pair(-1, e.what());
		} catch (DKIM::PermanentError& e) {
			if (pub.SoftFail())
				dkimResult[sig.GetDomain()] = std::make_pair(1, e.what());
			else
				dkimResult[sig.GetDomain()] = std::make_pair(0, e.what());
		}
	}

	for (std::list<std::string>::const_iterator i = senders.begin(); i != senders.end(); ++i)
	{
		std::string query = "_adsp._domainkey." + *i;
		std::string adspRecord;

		ADSP tmp;
		tmp.SetDomain(*i);

		std::map<std::string, std::pair<int, std::string> >::const_iterator dIter = dkimResult.find(*i);

		if (dIter != dkimResult.end() && dIter->second.first == -1) {
			tmp.SetResult(ADSP::DKIM_ADSP_TEMPERROR, dIter->second.second);
		} else if (dIter != dkimResult.end() && dIter->second.first == 1) {
			tmp.SetResult(ADSP::DKIM_ADSP_PASS, dIter->second.second);
		} else {
			std::string error;
			if (dIter != dkimResult.end())
				error = dIter->second.second;
			else
				error = "no dkim signature found for d=" + *i;

			if ((CustomDNSResolver?
						CustomDNSResolver(query, adspRecord, CustomDNSData):
						DKIM::Util::Resolver().GetTXT(query, adspRecord)
				))
			{
				// only bad queries goes here..
				if (!adspRecord.empty())
				{
					try {
						TagList tagList;
						tagList.Parse(adspRecord);
						TagListEntry v;
						if (tagList.GetTag("dkim", v))
						{
							if (v.GetValue() == "all") {
								tmp.SetResult(ADSP::DKIM_ADSP_FAIL, error);
							} else if (v.GetValue() == "discardable") {
								tmp.SetResult(ADSP::DKIM_ADSP_DISCARD, error);
							} else {
								tmp.SetResult(ADSP::DKIM_ADSP_UNKNOWN, error);
							}
						} else {
							tmp.SetResult(ADSP::DKIM_ADSP_UNKNOWN, error);
						}
					} catch (DKIM::TemporaryError& e) {
						tmp.SetResult(ADSP::DKIM_ADSP_TEMPERROR, e.what());
					} catch (DKIM::PermanentError& e) {
						tmp.SetResult(ADSP::DKIM_ADSP_PERMERROR, e.what());
					}
				} else {
					tmp.SetResult(ADSP::DKIM_ADSP_NONE, error);
				}
			} else {
				tmp.SetResult(ADSP::DKIM_ADSP_TEMPERROR, DKIM::Util::StringFormat("dns query failed for %s", query.c_str()));
			}
		}
		adsp.push_back(tmp);
	}
}
