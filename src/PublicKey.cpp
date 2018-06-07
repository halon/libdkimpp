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
#include <openssl/evp.h>
#include <openssl/pem.h>

using DKIM::PublicKey;
using DKIM::Conversion::Base64_Decode;
using DKIM::Util::StringFormat;

void PublicKey::Reset()
{
	m_tagList.Reset();

	// tag-h
	m_digestAlgorithms.clear();
	// tag-p
	RSA_free(m_publicKeyRSA);
	m_publicKeyRSA = NULL;
	m_publicKeyED25519.clear();
	m_signatureAlgorithm = DKIM_SA_RSA;
	// tag-s
	m_serviceType.clear();
	// tag-t
	m_flags.clear();
}

void PublicKey::Parse(const std::string& signature) throw (DKIM::PermanentError)
{
	m_tagList.Parse(signature);

	/**
	 * Validate Signature according to RFC-6376
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
				m_digestAlgorithms.push_back(DKIM_A_SHA256);
			else if (*a == "sha1")
				m_digestAlgorithms.push_back(DKIM_A_SHA1);
		}
	}

	// Key type
	TagListEntry k;
	if (m_tagList.GetTag("k", k))
	{
		if (k.GetValue() == "rsa")
			m_signatureAlgorithm = DKIM_SA_RSA;
		else if (k.GetValue() == "ed25519")
			m_signatureAlgorithm = DKIM_SA_ED25519;
		else
			throw DKIM::PermanentError(StringFormat("Unsupported key type %s (k supports rsa and ed25519)",
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

	switch (m_signatureAlgorithm)
	{
		case DKIM_SA_RSA:
		{
			std::string tmp = Base64_Decode(ptmp);
			const unsigned char *tmp2 = (const unsigned char*)tmp.c_str();
			EVP_PKEY* publicKey = d2i_PUBKEY(NULL, &tmp2, tmp.size());

			if (publicKey == NULL)
				throw DKIM::PermanentError("Public key could not be loaded (invalid DER data)");

#if OPENSSL_VERSION_NUMBER < 0x10100000
			if (publicKey->type != EVP_PKEY_RSA && publicKey->type != EVP_PKEY_RSA2)
			{
#else
			if (EVP_PKEY_base_id(publicKey) != EVP_PKEY_RSA && EVP_PKEY_base_id(publicKey) != EVP_PKEY_RSA2)
			{
				EVP_PKEY_free(publicKey);
#endif
				throw DKIM::PermanentError("Public key could not be loaded (key type must be RSA/RSA2)");
			}

			m_publicKeyRSA = EVP_PKEY_get1_RSA(publicKey);
			EVP_PKEY_free(publicKey);
		}
		break;
		case DKIM_SA_ED25519:
		{
			std::string tmp = Base64_Decode(ptmp);
			if (tmp.size() != 32)
				throw DKIM::PermanentError("Public ed25519 key could not be loaded");
			m_publicKeyED25519 = tmp;
		}
		break;
	}

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
