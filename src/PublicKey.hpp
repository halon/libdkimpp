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
#ifndef _DKIM_PUBLICKEY_HPP_
#define _DKIM_PUBLICKEY_HPP_

#include "DKIM.hpp"
#include "TagList.hpp"

#include <string>
#include <list>
#include <stdexcept>
#include <algorithm>

#include <openssl/rsa.h>

namespace DKIM {
	class PublicKey
	{
		public:
			typedef enum { DKIM_S_EMAIL } ServiceType;

			PublicKey()
			: m_publicKeyRSA(NULL)
			{ Reset(); }

			~PublicKey()
			{ Reset(); }

			void Reset();
			void Parse(const std::string& signature) throw (DKIM::PermanentError);

			// Get Functions

			const std::list<Algorithm>& GetAlgorithms() const
			{ return m_algorithms; }

			RSA* GetRSAPublicKey() const
			{ return m_publicKeyRSA; }

			std::string GetED25519PublicKey() const
			{ return m_publicKeyED25519; }

			SignatureAlgorithm GetSignatureAlgorithm() const
			{ return m_signatureAlgorithm; }

			const std::list<ServiceType>& GetServiceType() const
			{ return m_serviceType; }

			const std::list<std::string>& GetFlags() const
			{ return m_flags; }

			bool SoftFail() const
			{
				if (find(m_flags.begin(), m_flags.end(), "y") != m_flags.end())
					return true;
				return false;
			}
		private:
			PublicKey(const PublicKey&);

			TagList m_tagList;

			std::list<Algorithm> m_algorithms;
			RSA* m_publicKeyRSA;
			std::string m_publicKeyED25519;
			SignatureAlgorithm m_signatureAlgorithm;
			std::list<ServiceType> m_serviceType;
			std::list<std::string> m_flags;
	};
}

#endif
