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
#include <sodium.h>

using DKIM::Validatory;

#include "Canonicalization.hpp"
#include "Util.hpp"
#include "Resolver.hpp"
#include "TagList.hpp"
#include "EncodedWord.hpp"
#include "Tokenizer.hpp"
#include "Exception.hpp"

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
: CustomDNSData(nullptr)
, m_file(stream)
{
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
}

/*
 * GetSignature()
 *
 * Get the signature from supported header iterator
 */
void Validatory::GetSignature(const Message::HeaderList::const_iterator& headerIter,
		DKIM::Signature& sig)
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
{
	std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> evpmdbody(EVP_MD_CTX_create(), [] (EVP_MD_CTX* p) { EVP_MD_CTX_destroy(p); });

	// create signature for our body (message data)
	switch (sig.GetDigestAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_DigestInit_ex(evpmdbody.get(), EVP_sha1(), nullptr);
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_DigestInit_ex(evpmdbody.get(), EVP_sha256(), nullptr);
			break;
	}

	DKIM::Conversion::EVPDigest evpupd;
	evpupd.ctx = evpmdbody.get();

	CanonicalizationBody(m_file,
			sig.GetCanonModeBody(),
			m_msg.GetBodyOffset(),
			sig.GetBodySizeLimit(),
			sig.GetBodySize(),
			std::bind(&DKIM::Conversion::EVPDigest::update, &evpupd, std::placeholders::_1, std::placeholders::_2));

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_DigestFinal_ex(evpmdbody.get(), md_value, &md_len);

	if (sig.GetBodyHash().size() != md_len ||
			memcmp(sig.GetBodyHash().c_str(), md_value, md_len) != 0)
	{
		throw DKIM::PermanentError("Body hash did not verify", AR_FAIL);
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
{
	// sanity checking (between sig and pub)
	if (pub.GetDigestAlgorithms().size() > 0)
		if (find(pub.GetDigestAlgorithms().begin(), pub.GetDigestAlgorithms().end(), sig.GetDigestAlgorithm()) == pub.GetDigestAlgorithms().end())
			throw DKIM::PermanentError("Algorithm is not allowed");

	if (sig.GetSignatureAlgorithm() != pub.GetSignatureAlgorithm())
		throw DKIM::PermanentError("Signature algorithm type mismatch");

	if (!sig.IsARC())
	{
		if (find(pub.GetFlags().begin(), pub.GetFlags().end(), "s") != pub.GetFlags().end())
			if (sig.GetDomain() != sig.GetMailDomain())
				throw DKIM::PermanentError("Domain must match sub-domain (flag s)");
	}

	// create signature for our header
	std::unique_ptr<EVP_MD_CTX, std::function<void(EVP_MD_CTX*)>> evpmdhead(EVP_MD_CTX_create(), [] (EVP_MD_CTX* p) { EVP_MD_CTX_destroy(p); });
	int md_nid;
	switch (sig.GetDigestAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_DigestInit_ex(evpmdhead.get(), EVP_sha1(), nullptr);
			md_nid = NID_sha1;
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_DigestInit_ex(evpmdhead.get(), EVP_sha256(), nullptr);
			md_nid = NID_sha256;
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
		EVP_DigestUpdate(evpmdhead.get(), tmp.c_str(), tmp.size());
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
	EVP_DigestUpdate(evpmdhead.get(), tmp.c_str(), tmp.size());

	unsigned char md[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_DigestFinal_ex(evpmdhead.get(), md, &md_len);

	// verify the header signature
	switch (sig.GetSignatureAlgorithm())
	{
		case DKIM::DKIM_SA_RSA:
		{
			int r = RSA_verify(md_nid,
						md,
						md_len,
						(const unsigned char *)sig.GetSignatureData().c_str(),
						(unsigned int)sig.GetSignatureData().size(),
						pub.GetRSAPublicKey());
			if (r != 1)
				throw DKIM::PermanentError("Signature did not verify", AR_FAIL);
		}
		break;
		case DKIM::DKIM_SA_ED25519:
			if (crypto_sign_verify_detached((const unsigned char*)sig.GetSignatureData().c_str(),
						md,
						md_len,
						(const unsigned char *)pub.GetED25519PublicKey().c_str()) != 0)
					throw DKIM::PermanentError("Signature did not verify", AR_FAIL);
		break;
	}

	// success!
}
