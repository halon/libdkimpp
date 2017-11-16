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
#include "Signatory.hpp"

using DKIM::Signatory;

#include "Canonicalization.hpp"

using DKIM::Conversion::CanonicalizationHeader;
using DKIM::Conversion::CanonicalizationBody;

#include "Base64.hpp"

using DKIM::Conversion::Base64_Encode;

#include "Util.hpp"

using DKIM::Util::Algorithm2String;
using DKIM::Util::CanonMode2String;
using DKIM::Util::StringFormat;

#include <algorithm>
#include <map>

Signatory::Signatory(std::istream& file)
: m_file(file)
, m_ctx_head(NULL)
, m_ctx_body(NULL)
{
	m_ctx_head = EVP_MD_CTX_create();
	m_ctx_body = EVP_MD_CTX_create();
}

Signatory::~Signatory()
{
	EVP_MD_CTX_destroy(m_ctx_head);
	EVP_MD_CTX_destroy(m_ctx_body);
}

std::string Signatory::CreateSignature(const SignatoryOptions& options)
	throw (DKIM::PermanentError)
{
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX_cleanup(m_ctx_head);
	EVP_MD_CTX_cleanup(m_ctx_body);
#endif

	while (m_msg.ParseLine(m_file) && !m_msg.IsDone()) { }

	// create signature for our body (message data)
	switch (options.GetAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_DigestInit(m_ctx_body, EVP_sha1());
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_DigestInit(m_ctx_body, EVP_sha256());
			break;
	}

	CanonicalizationBody canonicalbody(options.GetCanonModeBody());

	// if we should limit the size of the body we hash
	bool limitBody = options.GetBodySignLength();
	size_t bodySize = options.GetBodyLength();

	// if we have a message: seek to GetBodyOffset()
	if (m_msg.GetBodyOffset() != -1)
	{
		m_file.clear();
		m_file.seekg(m_msg.GetBodyOffset());

		std::string s;
		while (std::getline(m_file, s) || m_file.peek() != EOF)
		{
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
					EVP_DigestUpdate(m_ctx_body, i->c_str(),
							limitBody?std::min(i->size(), bodySize):i->size());
					bodySize -= std::min(i->size(), bodySize);
				}
			}
		}
	}

	// else call (Done) -- which may insert a last CRLF if the body was empty
	if (m_msg.GetBodyOffset() == -1 || m_file.peek() == EOF)
	{
		std::vector<std::string> output;
		if (canonicalbody.Done(output))
		{
			for (std::vector<std::string>::const_iterator i = output.begin();
					i != output.end(); ++i)
			{
				if (limitBody && bodySize == 0) break;
				EVP_DigestUpdate(m_ctx_body, i->c_str(),
						limitBody?std::min(i->size(), bodySize):i->size());
				bodySize -= std::min(i->size(), bodySize);
			}
		}
	}
	if (limitBody && bodySize > 0)
		throw DKIM::PermanentError("Body sign limit exceed the size of the canonicalized message length");

	unsigned char md_value[EVP_MAX_MD_SIZE];
	unsigned int md_len;
	EVP_DigestFinal(m_ctx_body, md_value, &md_len);

	std::string bh((char*)md_value, md_len);

	// create signature for our header
	switch (options.GetAlgorithm())
	{
		case DKIM::DKIM_A_SHA1:
			EVP_SignInit(m_ctx_head, EVP_sha1());
			break;
		case DKIM::DKIM_A_SHA256:
			EVP_SignInit(m_ctx_head, EVP_sha256());
			break;
	}

	CanonicalizationHeader canonicalhead(options.GetCanonModeHeader());

	std::list<std::string> headersToSign = options.GetHeaders();
	std::list<std::string> signedHeaders;

	bool signAll = false;
	if (headersToSign.empty()) signAll = true;

	// add all headers to our cache (they will be pop of the end)
	std::map<std::string, Message::HeaderList> headerCache;
	for (const auto & hIter : m_msg.GetHeaders())
	{
		std::string name = hIter->GetName();
		transform(name.begin(), name.end(), name.begin(), tolower);

		headerCache[name].push_back(hIter);
		if (signAll)
			headersToSign.push_back(name);
	}

	while (!headersToSign.empty())
	{
		std::string tmp;
		std::string name = headersToSign.front();
		if (!name.empty())
		{
			transform(name.begin(), name.end(), name.begin(), tolower);

			std::map<std::string, Message::HeaderList>::iterator head = headerCache.find(name);
			if (head == headerCache.end() || head->second.empty())
			{
				if (options.GetSignEmptyHeaders())
					tmp = canonicalhead.FilterHeader(name + ":\r\n");
			} else {
				tmp = canonicalhead.FilterHeader(head->second.back()->GetHeader()) + "\r\n";
				head->second.pop_back();
			}
			if (!tmp.empty())
			{
				EVP_SignUpdate(m_ctx_head, tmp.c_str(), tmp.size());
				signedHeaders.push_back(name);
			}
		}
		headersToSign.pop_front();
	}

	std::string dkimHeader;
	dkimHeader += "DKIM-Signature: v=1; a=" + Algorithm2String(options.GetAlgorithm()) + "; c="
				+ CanonMode2String(options.GetCanonModeHeader()) + "/" + CanonMode2String(options.GetCanonModeBody()) + ";\r\n";

	std::string limit;
	if (options.GetBodySignLength())
		limit = StringFormat("; l=%lu", options.GetBodyLength());

	dkimHeader += "\td=" + options.GetDomain() + "; s=" + options.GetSelector() + limit + ";\r\n";

	std::string headerlist = "\th=";
	for (std::list<std::string>::const_iterator i = signedHeaders.begin();
		i != signedHeaders.end(); ++i)
	{
		bool insertColon = (i == signedHeaders.begin())?false:true;
		if (headerlist.size() + i->size() + (insertColon?1:0) > 80)
		{
			dkimHeader += headerlist + (insertColon?":":"") + "\r\n";
			headerlist = "\t " + *i;
		} else {
			headerlist += (insertColon?":":"") + *i;
		}
	}
	dkimHeader += headerlist + ";\r\n";
	dkimHeader += "\tbh=" + Base64_Encode(bh) + ";\r\n";
	dkimHeader += "\tb=";

	std::string tmp2 = canonicalhead.FilterHeader(dkimHeader);
	EVP_SignUpdate(m_ctx_head, tmp2.c_str(), tmp2.size());

	unsigned int len;
	unsigned char* data = new unsigned char[EVP_PKEY_size(options.GetPrivateKey())];
	if (EVP_SignFinal(m_ctx_head,
				data,
				&len,
				options.GetPrivateKey()
				) != 1) {
		delete [] data;
		throw DKIM::PermanentError("Message could not be signed");
	}
#if OPENSSL_VERSION_NUMBER < 0x10100000
	EVP_MD_CTX_cleanup(m_ctx_head);
#else
	EVP_MD_CTX_reset(m_ctx_head);
#endif

	std::string tmp3((const char*)data, len);
	delete [] data;

	size_t offset = 3; // "\tb=";
	std::string split = Base64_Encode(tmp3);
	while (!split.empty())
	{
		dkimHeader += split.substr(0, 80 - offset);
		split.erase(0, 80 - offset);
		if (!split.empty())
			dkimHeader += "\r\n\t ";
		offset = 2; // "\t ";
	}

	return dkimHeader;
}
