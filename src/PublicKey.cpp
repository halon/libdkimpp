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
#include "PublicKey.hpp"

#include "Base64.hpp"
#include "Tokenizer.hpp"
#include "Util.hpp"

#include <algorithm>

using DKIM::PublicKey;
using DKIM::Conversion::Base64;
using DKIM::Util::StringFormat;

void PublicKey::Reset()
{
	m_tagList.Reset();

	// tag-g
	m_localPart = "*";
	// tag-h
	m_algorithms.clear();
	// tag-p
	if (m_publicKey)
	{
		if (m_publicKey)
			EVP_PKEY_free(m_publicKey);
		m_publicKey = 0x0;
	}
	// tag-s
	m_serviceType.clear();
	// tag-t
	m_flags.clear();
}

void PublicKey::Parse(const std::string& signature) throw (DKIM::PermanentError)
{
	m_tagList.Parse(signature);

	/**
	 * Validate Signature according to RFC-4871
	 */

	// Version
	TagListEntry v;
	if (m_tagList.GetTag("v", v))
	{
		if (v.GetValue() != "DKIM1")
			throw DKIM::PermanentError(StringFormat("Unsupported version %s (v supports DKIM1)",
						v.GetValue().c_str()
						)
					);
	}

	// Granularity of the key (localpart)
	TagListEntry g;
	if (m_tagList.GetTag("g", g))
		m_localPart	= g.GetValue();

	// Acceptable hash algorithms
	TagListEntry h;
	if (m_tagList.GetTag("h", h))
	{
		if (h.GetValue().empty())
			throw DKIM::PermanentError("Acceptable hash algorithms is empty (h)");

		std::list<std::string> algo = DKIM::Tokenizer::ValueList(h.GetValue());
		for (std::list<std::string>::const_iterator a = algo.begin();
				a != algo.end(); ++a)
		{
			if (*a == "sha256")
				m_algorithms.push_back(DKIM_A_SHA256);
			else if (*a == "sha1")
				m_algorithms.push_back(DKIM_A_SHA1);
		}
	}

	// Key type
	TagListEntry k;
	if (m_tagList.GetTag("k", k))
	{
		if (k.GetValue() != "rsa")
			throw DKIM::PermanentError(StringFormat("Unsupported key type %s (k supports rsa)",
						k.GetValue().c_str()
						)
					);
	}

	// Public-key data
	TagListEntry p;
	if (!m_tagList.GetTag("p", p))
		throw DKIM::PermanentError("Missing public key (p)");
	
	if (p.GetValue().empty())
		throw DKIM::PermanentError("Public key is revoked (p)");

	std::string ptmp = p.GetValue();
	ptmp.erase(remove_if(ptmp.begin(), ptmp.end(), isspace), ptmp.end());

	std::string tmp = Base64::Decode(ptmp);
	const unsigned char *tmp2 = (const unsigned char*)tmp.c_str();
	m_publicKey = d2i_PUBKEY(NULL, &tmp2, tmp.size());

	if (m_publicKey == 0x0)
		throw DKIM::PermanentError("Public key could not be loaded (invalid DER data)");

	if (m_publicKey->type != EVP_PKEY_RSA && m_publicKey->type != EVP_PKEY_RSA2)
		throw DKIM::PermanentError("Public key could not be loaded (key type must be RSA/RSA2)");

	// Service Type
	TagListEntry s;
	if (m_tagList.GetTag("s", s))
	{
		if (s.GetValue().empty())
			throw DKIM::PermanentError("Service type is empty (s)");

		std::list<std::string> type = DKIM::Tokenizer::ValueList(s.GetValue());
		for (std::list<std::string>::const_iterator a = type.begin();
				a != type.end(); ++a)
		{
			if (*a == "email")
				m_serviceType.push_back(DKIM_S_EMAIL);
			else if (*a == "*")
			{
				m_serviceType.clear();
				break;
			}
		}
	}

	// Flags
	TagListEntry t;
	if (m_tagList.GetTag("t", t))
	{
		m_flags = DKIM::Tokenizer::ValueList(t.GetValue());
	}

	return;
}
