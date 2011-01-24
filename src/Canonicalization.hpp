/*
 *
 * Copyright (C) 2009,2010,2011 Halon Security <support@halon.se>
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

namespace DKIM {
	namespace Conversion {
		class CanonicalizationHeader
		{
			public:
				CanonicalizationHeader(CanonMode type);
				void SetType(CanonMode type);

				std::string FilterHeader(const std::string& input) const;
			private:
				CanonMode m_type;
		};
		class CanonicalizationBody
		{
			public:
				CanonicalizationBody(CanonMode type);
				void SetType(CanonMode type);
				void Reset();

				size_t FilterLine(const std::string& input, std::vector<std::string>& output);
				size_t Done(std::vector<std::string>& output);
			private:
				CanonMode m_type;
				size_t m_emptyLines;
				bool m_emptyBody;
		};
	}
}

#endif
