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
#include <sodium.h>

using DKIM::SignatoryOptions;
using DKIM::AdditionalSignaturesOptions;

SignatoryOptions::SignatoryOptions()
{
	m_signatures.push_front(AdditionalSignaturesOptions());
	auto & f = m_signatures.front();
	m_privateKeyRSA = &f.m_privateKeyRSA;
	m_privateKeyRSAFree = &f.m_privateKeyRSAFree;
	m_privateKeyED25519 = &f.m_privateKeyED25519;
	m_selector = &f.m_selector;
	m_domain = &f.m_domain;
	m_signatureAlgorithm = &f.m_signatureAlgorithm;
	m_digestAlgorithm = DKIM_A_SHA256;
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
	m_arcInstance = 0;

	m_timestampSign = false;
	m_timestamp = -1;
	m_expirationSign = false;
	m_expiration = -1;
	m_expirationAbsolute = true;
}

SignatoryOptions::~SignatoryOptions()
{
}

SignatoryOptions& SignatoryOptions::SetPrivateKey(const std::string& privatekey)
{
	switch (*m_signatureAlgorithm)
	{
		case DKIM_SA_RSA:
		{
			if (privatekey.substr(0, 5) == "-----")
			{
				BIO *o = BIO_new(BIO_s_mem());
				if (!o)
					throw DKIM::PermanentError("BIO could not be created for RSA key");
				BIO_write(o, privatekey.c_str(), privatekey.size());
				(void) BIO_flush(o);
				EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(o, nullptr, nullptr, nullptr);
				BIO_free_all(o);
				if (!privateKey)
					throw DKIM::PermanentError("RSA key could not be loaded from PEM");

#if OPENSSL_VERSION_NUMBER < 0x10100000
				if (privateKey->type != EVP_PKEY_RSA && privateKey->type != EVP_PKEY_RSA2)
#else
				if (EVP_PKEY_base_id(privateKey) != EVP_PKEY_RSA && EVP_PKEY_base_id(privateKey) != EVP_PKEY_RSA2)
#endif
				{
					EVP_PKEY_free(privateKey);
					throw DKIM::PermanentError("Private key could not be loaded (key type must be RSA/RSA2)");
				}

				*m_privateKeyRSA = EVP_PKEY_get1_RSA(privateKey);
				EVP_PKEY_free(privateKey);
			} else {
				/*
				 * Expect the data to be in DER format)
				 */

				std::string tmp = DKIM::Conversion::Base64_Decode(privatekey);
				const unsigned char *tmp2 = (const unsigned char*)tmp.c_str();
				*m_privateKeyRSA = d2i_RSAPrivateKey(nullptr, &tmp2, tmp.size());
				if (!*m_privateKeyRSA)
					throw DKIM::PermanentError("RSA key could not be loaded from DER");
			}
		}
		break;
		case DKIM_SA_ED25519:
		{
			auto seed_keypair = [](const std::string& seed) -> std::string
			{
				unsigned char pk[crypto_sign_PUBLICKEYBYTES] = { 0 };
				unsigned char sk[crypto_sign_SECRETKEYBYTES] = { 0 };
				crypto_sign_seed_keypair(pk, sk, (const unsigned char *)seed.c_str());
				return std::string((char*)sk, crypto_sign_SECRETKEYBYTES);
			};
			if (privatekey.size() == crypto_sign_SECRETKEYBYTES)
				*m_privateKeyED25519 = privatekey;
			else if (privatekey.size() == crypto_sign_SEEDBYTES)
				*m_privateKeyED25519 = seed_keypair(privatekey);
			else
			{
				std::string tmp = DKIM::Conversion::Base64_Decode(privatekey);
				if (tmp.size() == crypto_sign_SECRETKEYBYTES)
					*m_privateKeyED25519 = tmp;
				else if (tmp.size() == crypto_sign_SEEDBYTES)
					*m_privateKeyED25519 = seed_keypair(tmp);
				else
					throw DKIM::PermanentError("ED25519 key could not be loaded as Base64");
			}
		}
		break;
	}
	return *this;
}

SignatoryOptions& SignatoryOptions::SetRSAPrivateKey(RSA* privatekey, bool privatekeyfree)
{
	*m_privateKeyRSA = privatekey;
	*m_privateKeyRSAFree = privatekeyfree;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetSelector(const std::string& selector)
{
	if (!DKIM::Util::ValidateDomain(selector))
		throw DKIM::PermanentError("Invalid selector (s=)");

	*m_selector = selector;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetDomain(const std::string& domain)
{
	if (!DKIM::Util::ValidateDomain(domain))
		throw DKIM::PermanentError("Invalid domain (d=)");

	*m_domain = domain;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetDigestAlgorithm(DigestAlgorithm algorithm)
{
	m_digestAlgorithm = algorithm;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm)
{
	*m_signatureAlgorithm = signatureAlgorithm;
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

SignatoryOptions& SignatoryOptions::SetOversignHeaders(const std::list<std::string>& headers)
{
	m_oversignheaders = headers;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetSignBodyLength(unsigned long bodylength)
{
	m_bodyLength = bodylength;
	m_bodySignLength = true;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetARCInstance(unsigned long instance)
{
	m_arcInstance = instance;
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

SignatoryOptions& SignatoryOptions::SetTimestamp(time_t timestamp)
{
	m_timestamp = timestamp;
	m_timestampSign = true;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetExpiration(time_t expiration, bool absolute)
{
	m_expiration = expiration;
	m_expirationAbsolute = absolute;
	m_expirationSign = true;
	return *this;
}

SignatoryOptions& SignatoryOptions::SetIdentity(const std::string& identity)
{
	m_identity = identity;
	return *this;
}

AdditionalSignaturesOptions& SignatoryOptions::AddAdditionalSignature()
{
	m_signatures.push_back(AdditionalSignaturesOptions());
	return m_signatures.back();
}

AdditionalSignaturesOptions::AdditionalSignaturesOptions()
: m_privateKeyRSA(nullptr)
, m_privateKeyRSAFree(true)
{
	m_signatureAlgorithm = DKIM_SA_RSA;
}

AdditionalSignaturesOptions::~AdditionalSignaturesOptions()
{
	if (m_privateKeyRSAFree)
		RSA_free(m_privateKeyRSA);
}

AdditionalSignaturesOptions& AdditionalSignaturesOptions::SetRSAPrivateKey(RSA* privatekey, bool privatekeyfree)
{
	m_privateKeyRSA = privatekey;
	m_privateKeyRSAFree = privatekeyfree;
	return *this;
}

AdditionalSignaturesOptions& AdditionalSignaturesOptions::SetSelector(const std::string& selector)
{
	if (!DKIM::Util::ValidateDomain(selector))
		throw DKIM::PermanentError("Invalid selector (s=)");

	m_selector = selector;
	return *this;
}

AdditionalSignaturesOptions& AdditionalSignaturesOptions::SetDomain(const std::string& domain)
{
	if (!DKIM::Util::ValidateDomain(domain))
		throw DKIM::PermanentError("Invalid domain (d=)");

	m_domain = domain;
	return *this;
}

AdditionalSignaturesOptions& AdditionalSignaturesOptions::SetSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm)
{
	m_signatureAlgorithm = signatureAlgorithm;
	return *this;
}

AdditionalSignaturesOptions& AdditionalSignaturesOptions::SetPrivateKey(const std::string& privatekey)
{
	switch (m_signatureAlgorithm)
	{
		case DKIM_SA_RSA:
		{
			if (privatekey.substr(0, 5) == "-----")
			{
				BIO *o = BIO_new(BIO_s_mem());
				if (!o)
					throw DKIM::PermanentError("BIO could not be created for RSA key");
				BIO_write(o, privatekey.c_str(), privatekey.size());
				(void) BIO_flush(o);
				EVP_PKEY* privateKey = PEM_read_bio_PrivateKey(o, nullptr, nullptr, nullptr);
				BIO_free_all(o);
				if (!privateKey)
					throw DKIM::PermanentError("RSA key could not be loaded from PEM");

#if OPENSSL_VERSION_NUMBER < 0x10100000
				if (privateKey->type != EVP_PKEY_RSA && privateKey->type != EVP_PKEY_RSA2)
#else
				if (EVP_PKEY_base_id(privateKey) != EVP_PKEY_RSA && EVP_PKEY_base_id(privateKey) != EVP_PKEY_RSA2)
#endif
				{
					EVP_PKEY_free(privateKey);
					throw DKIM::PermanentError("Private key could not be loaded (key type must be RSA/RSA2)");
				}

				m_privateKeyRSA = EVP_PKEY_get1_RSA(privateKey);
				EVP_PKEY_free(privateKey);
			} else {
				/*
				 * Expect the data to be in DER format)
				 */

				std::string tmp = DKIM::Conversion::Base64_Decode(privatekey);
				const unsigned char *tmp2 = (const unsigned char*)tmp.c_str();
				m_privateKeyRSA = d2i_RSAPrivateKey(nullptr, &tmp2, tmp.size());
				if (!m_privateKeyRSA)
					throw DKIM::PermanentError("RSA key could not be loaded from DER");
			}
		}
		break;
		case DKIM_SA_ED25519:
		{
			auto seed_keypair = [](const std::string& seed) -> std::string
			{
				unsigned char pk[crypto_sign_PUBLICKEYBYTES] = { 0 };
				unsigned char sk[crypto_sign_SECRETKEYBYTES] = { 0 };
				crypto_sign_seed_keypair(pk, sk, (const unsigned char *)seed.c_str());
				return std::string((char*)sk, crypto_sign_SECRETKEYBYTES);
			};
			if (privatekey.size() == crypto_sign_SECRETKEYBYTES)
				m_privateKeyED25519 = privatekey;
			else if (privatekey.size() == crypto_sign_SEEDBYTES)
				m_privateKeyED25519 = seed_keypair(privatekey);
			else
			{
				std::string tmp = DKIM::Conversion::Base64_Decode(privatekey);
				if (tmp.size() == crypto_sign_SECRETKEYBYTES)
					m_privateKeyED25519 = tmp;
				else if (tmp.size() == crypto_sign_SEEDBYTES)
					m_privateKeyED25519 = seed_keypair(tmp);
				else
					throw DKIM::PermanentError("ED25519 key could not be loaded as Base64");
			}
		}
		break;
	}
	return *this;
}