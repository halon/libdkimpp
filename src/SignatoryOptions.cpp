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
#include "SignatoryOptions.hpp"
#include "Util.hpp"

using DKIM::SignatoryOptions;

SignatoryOptions::SignatoryOptions()
: m_privateKey(NULL), m_rsa(NULL)
{
	m_algorithm = DKIM_A_SHA256;
	m_canonHead = DKIM_C_SIMPLE;
	m_canonBody = DKIM_C_SIMPLE;

	// headers that should (recommendation) be signed according to the RFC
	m_headers.push_back("from");
	m_headers.push_back("sender");
	m_headers.push_back("reply-to");
	m_headers.push_back("subject");
	m_headers.push_back("date");
	m_headers.push_back("message-id");
	m_headers.push_back("to");
	m_headers.push_back("cc");
	m_headers.push_back("mime-version");
	m_headers.push_back("content-type");
	m_headers.push_back("content-transfer-encoding");
	m_headers.push_back("content-id");
	m_headers.push_back("content-description");
	m_headers.push_back("resent-date");
	m_headers.push_back("resent-from");
	m_headers.push_back("resent-sender");
	m_headers.push_back("resent-to");
	m_headers.push_back("resent-cc");
	m_headers.push_back("resent-message-id");
	m_headers.push_back("in-reply-to");
	m_headers.push_back("references");
	m_headers.push_back("list-id");
	m_headers.push_back("list-help");
	m_headers.push_back("list-unsubscribe");
	m_headers.push_back("list-subscribe");
	m_headers.push_back("list-post");
	m_headers.push_back("list-owner");
	m_headers.push_back("list-archive");

	m_bodyLength = 0;	
	m_bodySignLength = false;
}

SignatoryOptions::~SignatoryOptions()
{
	RSA_free(m_rsa);
	EVP_PKEY_free(m_privateKey);
}

SignatoryOptions& SignatoryOptions::SetPrivateKey(const std::string& privatekey)
{
	if (privatekey.substr(0, 5) == "-----")
	{
		BIO *o = BIO_new(BIO_s_mem());
		if (!o)
			throw DKIM::PermanentError("BIO could not be created for RSA key");
		BIO_write(o, privatekey.c_str(), privatekey.size());
		(void) BIO_flush(o);
		m_privateKey = PEM_read_bio_PrivateKey(o, NULL, NULL, NULL);
		BIO_free_all(o);
		if (!m_privateKey)
			throw DKIM::PermanentError("RSA key could not be loaded from PEM");

#if OPENSSL_VERSION_NUMBER < 0x10100000
		if (m_privateKey->type != EVP_PKEY_RSA && m_privateKey->type != EVP_PKEY_RSA2)
#else
		if (EVP_PKEY_base_id(m_privateKey) != EVP_PKEY_RSA && EVP_PKEY_base_id(m_privateKey) != EVP_PKEY_RSA2)
#endif
			throw DKIM::PermanentError("Private key could not be loaded (key type must be RSA/RSA2)");
	} else {
		/*
		 * Expect the data to be in DER format)
		 */

		std::string tmp = DKIM::Conversion::Base64_Decode(privatekey);
		const unsigned char *tmp2 = (const unsigned char*)tmp.c_str();
		m_rsa = d2i_RSAPrivateKey(NULL, &tmp2, tmp.size());
		if (!m_rsa)
			throw DKIM::PermanentError("RSA key could not be loaded from DER");

		m_privateKey = EVP_PKEY_new();
		if (!m_privateKey)
			throw DKIM::PermanentError("PKEY could not be loaded");

		if (EVP_PKEY_assign_RSA(m_privateKey, m_rsa) != 1)
			throw DKIM::PermanentError("RSA could not be assigned to PKEY");

		m_rsa = NULL; // freed with pkey
	}
	return *this;
}

SignatoryOptions& SignatoryOptions::SetSelector(const std::string& selector)
{
	if (!DKIM::Util::ValidateDomain(selector))
		throw DKIM::PermanentError("Invalid selector (s=)");

	m_selector = selector;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetDomain(const std::string& domain)
{
	if (!DKIM::Util::ValidateDomain(domain))
		throw DKIM::PermanentError("Invalid domain (d=)");

	m_domain = domain;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetAlgorithm(Algorithm algorithm)
{
	m_algorithm = algorithm;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetHeaders(const std::list<std::string>& headers)
{
	m_headers = headers;
	return *this;
}

SignatoryOptions& SignatoryOptions::AddHeaders(const std::list<std::string>& headers)
{
	m_headers.insert(m_headers.end(), headers.begin(), headers.end());
	return *this;
}

SignatoryOptions& SignatoryOptions::SetSignBodyLength(unsigned long bodylength)
{
	m_bodyLength = bodylength;
	m_bodySignLength = true;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetCanonModeHeader(CanonMode mode)
{
	m_canonHead = mode;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetCanonModeBody(CanonMode mode)
{
	m_canonBody = mode;
	return *this;
}
