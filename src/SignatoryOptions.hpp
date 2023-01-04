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
#ifndef _DKIM_SIGNATORYOPTIONS_HPP_
#define _DKIM_SIGNATORYOPTIONS_HPP_

#include "Exception.hpp"
#include "DKIM.hpp"
#include "MailParser.hpp"
#include "Base64.hpp"

#include <list>
#include <string>
#include <time.h>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace DKIM
{
	class AdditionalSignaturesOptions
	{
		public:
			AdditionalSignaturesOptions();
			~AdditionalSignaturesOptions();

			AdditionalSignaturesOptions& SetPrivateKey(const std::string& privatekey);
			AdditionalSignaturesOptions& SetRSAPrivateKey(RSA* privatekey, bool privatekeyfree);
			AdditionalSignaturesOptions& SetDomain(const std::string& domain);
			AdditionalSignaturesOptions& SetSelector(const std::string& selector);
			AdditionalSignaturesOptions& SetSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm);

			RSA* GetRSAPrivateKey() const
			{ return m_privateKeyRSA; }
			std::string GetED25519PrivateKey() const
			{ return m_privateKeyED25519; }
			const std::string& GetDomain() const
			{ return m_domain; }
			const std::string& GetSelector() const
			{ return m_selector; }
			SignatureAlgorithm GetSignatureAlgorithm() const
			{ return m_signatureAlgorithm; }

			RSA* m_privateKeyRSA;
			bool m_privateKeyRSAFree;
			std::string m_privateKeyED25519;
			SignatureAlgorithm m_signatureAlgorithm;

			std::string m_domain;
			std::string m_selector;
	};
	class SignatoryOptions
	{
		public:
			SignatoryOptions();
			~SignatoryOptions();

			SignatoryOptions& SetPrivateKey(const std::string& privatekey);
			SignatoryOptions& SetRSAPrivateKey(RSA* privatekey, bool privatekeyfree);
			SignatoryOptions& SetDomain(const std::string& domain);
			SignatoryOptions& SetSelector(const std::string& selector);
			SignatoryOptions& SetDigestAlgorithm(DigestAlgorithm algorithm);
			SignatoryOptions& SetSignatureAlgorithm(SignatureAlgorithm signatureAlgorithm);
			SignatoryOptions& SetHeaders(const std::list<std::string>& headers);
			SignatoryOptions& AddHeaders(const std::list<std::string>& headers);
			SignatoryOptions& DelHeaders(const std::list<std::string>& headers);
			SignatoryOptions& SetOversignHeaders(const std::list<std::string>& headers);
			SignatoryOptions& SetSignBodyLength(unsigned long bodylength);
			SignatoryOptions& SetCanonModeHeader(CanonMode mode);
			SignatoryOptions& SetCanonModeBody(CanonMode mode);
			SignatoryOptions& SetARCInstance(unsigned long instance);
			SignatoryOptions& SetTimestamp(time_t timestamp);
			SignatoryOptions& SetExpiration(time_t expiration, bool absolute = true);
			SignatoryOptions& SetIdentity(const std::string& identity);
			AdditionalSignaturesOptions& AddAdditionalSignature();
			const std::list<AdditionalSignaturesOptions>& GetAdditionalSignatures() const
			{ return m_signatures; }

			RSA* GetRSAPrivateKey() const
			{ return *m_privateKeyRSA; }
			std::string GetED25519PrivateKey() const
			{ return *m_privateKeyED25519; }
			const std::string& GetDomain() const
			{ return *m_domain; }
			const std::string& GetSelector() const
			{ return *m_selector; }
			DigestAlgorithm GetDigestAlgorithm() const
			{ return m_digestAlgorithm; }
			SignatureAlgorithm GetSignatureAlgorithm() const
			{ return *m_signatureAlgorithm; }
			const std::list<std::string>& GetHeaders() const
			{ return m_headers; }
			const std::list<std::string>& GetOversignHeaders() const
			{ return m_oversignheaders; }
			unsigned long GetBodyLength() const
			{ return m_bodyLength; }
			bool GetBodySignLength() const
			{ return m_bodySignLength; }
			CanonMode GetCanonModeHeader() const
			{ return m_canonHead; }
			CanonMode GetCanonModeBody() const
			{ return m_canonBody; }
			unsigned long GetARCInstance() const
			{ return m_arcInstance; }
			bool GetTimestampSign() const
			{ return m_timestampSign; }
			time_t GetTimestamp() const
			{ return m_timestamp; }
			bool GetExpirationSign() const
			{ return m_expirationSign; }
			time_t GetExpiration() const
			{ return m_expiration; }
			bool GetExpirationAbsolute() const
			{ return m_expirationAbsolute; }
			const std::string& GetIdentity() const
			{ return m_identity; }
		private:
			SignatoryOptions(const SignatoryOptions&);

			RSA** m_privateKeyRSA;
			bool* m_privateKeyRSAFree;
			std::string* m_privateKeyED25519;
			SignatureAlgorithm* m_signatureAlgorithm;
			std::string* m_domain;
			std::string* m_selector;

			DigestAlgorithm m_digestAlgorithm;

			std::list<std::string> m_oversignheaders;
			std::list<std::string> m_headers;

			unsigned long m_bodyLength;
			bool m_bodySignLength;
			unsigned long m_arcInstance;

			CanonMode m_canonHead;
			CanonMode m_canonBody;

			bool m_timestampSign;
			time_t m_timestamp;
			bool m_expirationSign;
			bool m_expirationAbsolute;
			time_t m_expiration;

			std::string m_identity;
			std::list<AdditionalSignaturesOptions> m_signatures;
	};
}

#endif
