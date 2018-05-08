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

Validatory::Validatory(std::istream& stream, ValidatorType type)
: CustomDNSResolver(NULL)
, CustomDNSData(NULL)
, m_file(stream)
, m_ctx_head(NULL)
, m_ctx_body(NULL)
{
	m_ctx_head = EVP_MD_CTX_create();
	m_ctx_body = EVP_MD_CTX_create();

	while (m_msg.ParseLine(m_file) && !m_msg.IsDone()) { }

	if (type == NONE)
		return;

	DKIM::Message::HeaderList::const_iterator i;
	for (i = m_msg.GetHeaders().begin(); i != m_msg.GetHeaders().end(); ++i)
	{
		// headers should be matched in lower-case
		std::string headerName = (*i)->GetName();
		transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);

		// collect all signatures
		if ((type == DKIM && headerName == "dkim-signature") ||
			(type == ARC && headerName == "arc-message-signature"))
		{
			m_dkimHeaders.push_back(*i);
		}
	}
}

Validatory::~Validatory()
{
	EVP_MD_CTX_destroy(m_ctx_head);
	EVP_MD_CTX_destroy(m_ctx_body);
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
	sig.Parse(*headerIter);
	CheckBodyHash(sig);
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
 * CheckBodyHash()
 *
 * Validate the message according to rfc6376
 */
void Validatory::CheckBodyHash(const DKIM::Signature& sig)
	throw (DKIM::PermanentError)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX_cleanup(m_ctx_body);
#endif

	// create signature for our body (message data)
	switch (sig.GetAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_DigestInit(m_ctx_body, EVP_sha1());
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_DigestInit(m_ctx_body, EVP_sha256());
			break;
	}

	DKIM::Conversion::EVPDigest evpupd;
	evpupd.ctx = m_ctx_body;

	CanonicalizationBody(m_file,
			sig.GetCanonModeBody(),
			m_msg.GetBodyOffset(),
			sig.GetBodySizeLimit(),
			sig.GetBodySize(),
			std::bind(&DKIM::Conversion::EVPDigest::update, &evpupd, std::placeholders::_1, std::placeholders::_2));

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_DigestFinal(m_ctx_body, md_value, &md_len);

	if (sig.GetBodyHash().size() != md_len ||
			memcmp(sig.GetBodyHash().c_str(), md_value, md_len) != 0)
	{
		throw DKIM::PermanentError("Body hash did not verify");
	}
}

/*
 * CheckSignature()
 *
 * Validate the message according to rfc6376
 */
void Validatory::CheckSignature(const std::shared_ptr<DKIM::Header> header,
		const DKIM::Signature& sig,
		const DKIM::PublicKey& pub)
	throw (DKIM::PermanentError)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX_cleanup(m_ctx_head);
#endif

	// sanity checking (between sig and pub)
	if (pub.GetAlgorithms().size() > 0)
		if (find(pub.GetAlgorithms().begin(), pub.GetAlgorithms().end(), sig.GetAlgorithm()) == pub.GetAlgorithms().end())
			throw DKIM::PermanentError("Algorithm is not allowed");

	if (!sig.IsARC())
	{
		if (find(pub.GetFlags().begin(), pub.GetFlags().end(), "s") != pub.GetFlags().end())
			if (sig.GetDomain() != sig.GetMailDomain())
				throw DKIM::PermanentError("Domain must match sub-domain (flag s)");
	}

	// create signature for our header
	switch (sig.GetAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_VerifyInit(m_ctx_head, EVP_sha1());
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_VerifyInit(m_ctx_head, EVP_sha256());
			break;
	}

	CanonicalizationHeader canonicalhead(sig.GetCanonModeHeader());

	// add all headers to our cache (they will be pop of the end)
	std::map<std::string, Message::HeaderList> headerCache;
	for (const auto & hIter : m_msg.GetHeaders())
	{
		std::string headerName = hIter->GetName();
		transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);
		headerCache[headerName].push_back(hIter);
	}

	// add all signed headers to our hash
	for (auto name : sig.GetSignedHeaders())
	{
		std::string tmp;
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
		EVP_VerifyUpdate(m_ctx_head, tmp.c_str(), tmp.size());
	}

	// add our dkim-signature to the calculation (remove the "b"-tag)
	std::string h = header->GetHeader().substr(0, header->GetValueOffset());
	std::string v = header->GetHeader().substr(header->GetValueOffset());

	DKIM::TagListEntry bTag;
	sig.GetTag("b", bTag);
	v.erase((int)bTag.GetValueOffset(), bTag.GetValue().size());

	std::string tmp = canonicalhead.FilterHeader(h + v);
#ifdef DEBUG
	printf("[%s]\n", tmp.c_str());
#endif
	EVP_VerifyUpdate(m_ctx_head, tmp.c_str(), tmp.size());

	// verify the header signature
	if (EVP_VerifyFinal(m_ctx_head,
				(const unsigned char*)sig.GetSignatureData().c_str(),
				sig.GetSignatureData().size(),
				pub.GetPublicKey()
				) != 1)
		throw DKIM::PermanentError("Signature did not verify");
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX_cleanup(m_ctx_head);
#else
	EVP_MD_CTX_reset(m_ctx_head);
#endif

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

	for (const auto & i : m_msg.GetHeaders())
	{
		std::string headerName = i->GetName();
		transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);

		// find from: <...> header(s)...
		if (headerName == "from")
		{
			std::string header = i->GetHeader().substr(i->GetValueOffset());

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
			CheckSignature(*i, sig, pub);

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
