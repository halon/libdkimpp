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
#ifndef _DKIM_VALIDATORY_HPP_
#define _DKIM_VALIDATORY_HPP_

#include "Exception.hpp"
#include "PublicKey.hpp"
#include "Signature.hpp"
#include "MailParser.hpp"

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>
#include <functional>

namespace DKIM
{
	class Validatory
	{
		public:
			typedef enum { DKIM, ARC, NONE } ValidatorType;
			typedef std::shared_ptr<DKIM::Header> SignatureItem;
			typedef std::list<SignatureItem> SignatureList;

			Validatory(std::istream& file, ValidatorType type = DKIM);
			~Validatory();

			void GetSignature(const Message::HeaderList::const_iterator& headerIter,
					DKIM::Signature& sig)
				throw (DKIM::PermanentError);

			void CheckBodyHash(const DKIM::Signature& sig)
				throw (DKIM::PermanentError);

			void GetPublicKey(const DKIM::Signature& sig,
					DKIM::PublicKey& pub)
				throw (DKIM::PermanentError, DKIM::TemporaryError);

			void CheckSignature(const Message::HeaderList::const_iterator& headerIter,
					const DKIM::Signature& sig,
					const DKIM::PublicKey& pub)
				throw (DKIM::PermanentError)
			{
				CheckSignature(*headerIter, sig, pub);
			}

			void CheckSignature(const std::shared_ptr<DKIM::Header> header,
					const DKIM::Signature& sig,
					const DKIM::PublicKey& pub)
				throw (DKIM::PermanentError);

			const SignatureList& GetSignatures() const
				throw() {
				return m_dkimHeaders;
			}

			std::function<bool(const std::string&, std::string&, void*)> CustomDNSResolver;
			void *CustomDNSData;
		private:
			std::istream& m_file;
			DKIM::Message m_msg;

			SignatureList m_dkimHeaders;
	};
}

#endif
