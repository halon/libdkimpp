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
#ifndef _DKIM_UTIL_HPP_
#define _DKIM_UTIL_HPP_

#include "DKIM.hpp"

#define _MAX(x, y) ((x)>(y)?(x):(y))
#define _MIN(x, y) ((x)<(y)?(x):(y))

#include <string>

namespace DKIM {
	namespace Util {
		bool MatchWithWildCard(const std::string& pattern, const std::string& find);
		std::string CanonMode2String(CanonMode mode);
		std::string Algorithm2String(Algorithm algorithm);
		std::string StringFormat(const char* fmt, ...)
			__attribute__((format(printf, 1, 2)));
		bool ValidateDomain(const std::string& domain);
	}
}

#endif
