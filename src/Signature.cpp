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
#include "Signature.hpp"
#include "Tokenizer.hpp"
#include "QuotedPrintable.hpp"
#include "Base64.hpp"
#include "Util.hpp"
#include "Exception.hpp"

#include <cstdio>
#include <cstdlib>
#include <cerrno>
#include <algorithm>
#include <cstring>

using DKIM::Signature;
using DKIM::Conversion::Base64_Decode;
using DKIM::Conversion::QuotedPrintable;
using DKIM::Util::StringFormat;

void Signature::Reset()
{
	m_tagList.Reset();
	m_arc = false;

	// tag-a
	m_digestAlgorithm = DKIM_A_SHA256;
	m_signatureAlgorithm = DKIM_SA_RSA;
	// tag-b
	m_b = "";
	// tag-bh
	m_bh = "";
	// tag-c
	m_header = DKIM_C_SIMPLE;
	m_body = DKIM_C_SIMPLE;
	// tag-d
	m_domain = "";
	// tag-h
	m_headers.clear();
	// tag-i
	m_mailLocalPart = "";
	m_mailDomain = "";
	// tag-l
	m_bodySize = 0;
	m_bodySizeLimit = false;
	// tag-q
	m_queryType = DKIM_Q_DNSTXT;
	// tag-s
	m_selector = "";
	// tag-i-arc
	m_arcInstance = 0;
}

void Signature::Parse(const std::shared_ptr<DKIM::Header> header)
{
	m_tagList.Parse(header->GetHeader().substr(header->GetValueOffset()));

	std::string headerName = header->GetName();
	transform(headerName.begin(), headerName.end(), headerName.begin(), tolower);
	if (headerName == "arc-message-signature")
		m_arc = true;

	/**
	 * Validate Signature according to RFC-6376
	 */

	// Domain of the signing entity
	TagListEntry d;
	if (!m_tagList.GetTag("d", d))
		throw DKIM::PermanentError("Missing domain of the signing entity (d)");
	m_domain = d.GetValue();
	transform(m_domain.begin(), m_domain.end(), m_domain.begin(), tolower);

	// Version
	if (!m_arc)
	{
		TagListEntry v;
		if (!m_tagList.GetTag("v", v))
			throw DKIM::PermanentError("Missing version (v)");

		if (v.GetValue() != "1")
			throw DKIM::PermanentError(StringFormat("Unsupported version %s (v supports 1)",
						v.GetValue().c_str()
						)
					);
	}

	// Algorithm
	TagListEntry a;
	if (!m_tagList.GetTag("a", a))
		throw DKIM::PermanentError("Missing algorithm (a)");

	if (a.GetValue() == "rsa-sha256")
	{
		m_digestAlgorithm = DKIM_A_SHA256;
		m_signatureAlgorithm = DKIM_SA_RSA;
	}
	else if (a.GetValue() == "rsa-sha1")
	{
		m_digestAlgorithm = DKIM_A_SHA1;
		m_signatureAlgorithm = DKIM_SA_RSA;
	}
	else if (a.GetValue() == "ed25519-sha256")
	{
		m_digestAlgorithm = DKIM_A_SHA256;
		m_signatureAlgorithm = DKIM_SA_ED25519;
	}
	else
		throw DKIM::PermanentError(StringFormat("Unsupported signature algorithm %s (a supports rsa-sha1, rsa-sha256 and ed25519-sha256)",
					a.GetValue().c_str()
					)
				);

	// Signature data
	TagListEntry b;
	if (!m_tagList.GetTag("b", b) || b.GetValue().empty())
		throw DKIM::PermanentError("Missing header signature (b)");

	std::string btmp = b.GetValue();
	btmp.erase(remove_if(btmp.begin(), btmp.end(), isspace), btmp.end());
	m_b = Base64_Decode(btmp);

	// Hash of the canonicalized body
	TagListEntry bh;
	if (!m_tagList.GetTag("bh", bh))
			throw DKIM::PermanentError("Missing body hash (bh)");
	std::string bhtmp = bh.GetValue();
	bhtmp.erase(remove_if(bhtmp.begin(), bhtmp.end(), isspace), bhtmp.end());
	m_bh = Base64_Decode(bhtmp);

	// Message canonicalization
	TagListEntry c;
	if (m_tagList.GetTag("c", c))
	{
		std::string body, header;

		size_t split = c.GetValue().find('/');
		if (split == std::string::npos)
		{
			header = c.GetValue();
			body = "simple";
		} else {
			header = c.GetValue().substr(0, split);
			body = c.GetValue().substr(split + 1);
		}

		if (header == "relaxed")
			m_header = DKIM_C_RELAXED;
		else if (header == "simple")
			m_header = DKIM_C_SIMPLE;
		else
			throw DKIM::PermanentError(StringFormat("Unsupported canonicalization type %s (c supports simple, relaxed)",
						header.c_str()
						)
					);

		if (body == "relaxed")
			m_body = DKIM_C_RELAXED;
		else if (body == "simple")
			m_body = DKIM_C_SIMPLE;
		else
			throw DKIM::PermanentError(StringFormat("Unsupported canonicalization type %s (c supports simple, relaxed)",
						body.c_str()
						)
					);
	}

	// Signed header fields
	TagListEntry h;
	if (!m_tagList.GetTag("h", h))
		throw DKIM::PermanentError("Missing signed header fields (h)");
	m_headers = DKIM::Tokenizer::ValueList(h.GetValue());

	bool signedFrom = false;
	for (std::list<std::string>::const_iterator i = m_headers.begin(); i != m_headers.end(); ++i)
	{
		if (strcasecmp(i->c_str(), "from") == 0)
		{
			signedFrom = true;
			break;
		}
	}
	if (!signedFrom)
		throw DKIM::PermanentError("From: header must be included in signature");

	// Identity of the user or agent
	if (m_arc)
	{
		TagListEntry i;
		if (!m_tagList.GetTag("i", i))
			throw DKIM::PermanentError("Missing ARC instance (i)");
		m_arcInstance = strtoul(i.GetValue().c_str(), nullptr, 10);
		if (m_arcInstance < 1 || m_arcInstance > 50)
			throw DKIM::PermanentError("ARC instance (i) out of range 1-50");
	}
	else
	{
		TagListEntry i;
		if (!m_tagList.GetTag("i", i))
		{
			m_mailLocalPart = "";
			m_mailDomain = m_domain;
		} else {
			std::string mail = QuotedPrintable::Decode(i.GetValue());

			size_t mailsep = mail.find('@');
			if (mailsep == std::string::npos)
				throw DKIM::PermanentError("Missing a local-part (i)");

			m_mailLocalPart = mail.substr(0, mailsep);

			// m_mailDomain should be matched in lower-case
			m_mailDomain = mail.substr(mailsep+1);
			transform(m_mailDomain.begin(), m_mailDomain.end(), m_mailDomain.begin(), tolower);

			if (m_mailDomain == m_domain) {
				// same domain
			} else if (m_mailDomain.size() > m_domain.size() && ("." + m_domain) == m_mailDomain.substr(m_mailDomain.size() - m_domain.size() - 1)) {
				// same sub-domain (.domain =~ my.sub.domain)
			} else {
				throw DKIM::PermanentError(StringFormat("Domain %s is not a (sub)domain of %s (i does not match d)",
						m_mailDomain.c_str(),
						m_domain.c_str()
						)
					);
			}
		}
	}

	// Body length count
	TagListEntry l;
	if (m_tagList.GetTag("l", l))
	{
		if (l.GetValue().size() > 76)
			throw DKIM::PermanentError("Invalid body signed length; exceeds 76 digits (l)");

		char* ptr;
		unsigned long bs = strtoul(l.GetValue().c_str(), &ptr, 10);
		if (errno == ERANGE)
			throw DKIM::PermanentError("Invalid body signed length; exceeds available storage size of unsigned long (l)");
		if ((signed long)bs < 0)
			throw DKIM::PermanentError("Invalid body signed length; must be a positive number (l)");
		if (*ptr != '\0')
			throw DKIM::PermanentError("Invalid body signed length; failed numeric parsing (l)");
		m_bodySize = bs;
		m_bodySizeLimit = true;
	}

	// Query methods
	TagListEntry q;
	if (m_tagList.GetTag("q", q))
	{
		if (q.GetValue() == "dns/txt")
			m_queryType = DKIM_Q_DNSTXT;
		else
			throw DKIM::PermanentError(StringFormat("Unsupported query method %s (q supports dns/txt)",
						q.GetValue().c_str()
						)
					);
	}

	// Selector
	TagListEntry s;
	if (!m_tagList.GetTag("s", s))
		throw DKIM::PermanentError("Missing query selector (s)");
	m_selector = s.GetValue();

	// Signature Timestamp
	TagListEntry t;
	if (m_tagList.GetTag("t", t))
		; // ignored

	// Signature Expiration
	TagListEntry x;
	if (m_tagList.GetTag("x", x))
	{
		if (strtol(x.GetValue().c_str(), nullptr, 10) < time(nullptr))
			throw DKIM::PermanentError("Signature has expired (x)");
	}

	return;
}
