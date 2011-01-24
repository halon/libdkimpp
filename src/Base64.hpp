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
#ifndef _DKIM_BASE64_HPP_
#define _DKIM_BASE64_HPP_

#include "Exception.hpp"

#include <string>

namespace DKIM {
	namespace Conversion {
		class Base64 {
			public:
				static std::string Decode(const std::string& data)
					throw (DKIM::PermanentError);
				static std::string Encode(const std::string& data)
					throw (DKIM::PermanentError);
		};
	}
}

#endif
