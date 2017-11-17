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
#ifndef _DKIM_CANONICALIZATION_HPP_
#define _DKIM_CANONICALIZATION_HPP_

#include "DKIM.hpp"

#include <string>
#include <vector>
#include <functional>
#include <openssl/evp.h>

namespace DKIM {
	namespace Conversion {
		struct EVPDigest
		{
			EVP_MD_CTX* ctx;
			void update(const char* ptr, size_t i)
			{
				EVP_DigestUpdate(ctx, ptr, i);
			}
		};
		class CanonicalizationHeader
		{
			public:
				CanonicalizationHeader(CanonMode type);
				void SetType(CanonMode type);

				std::string FilterHeader(const std::string& input) const;
			private:
				CanonMode m_type;
		};
		bool CanonicalizationBody(std::istream& stream, CanonMode type, ssize_t bodyOffset, bool bodyLimit, size_t bodySize, std::function<void(const char *, size_t)> func);
	}
}

#endif
