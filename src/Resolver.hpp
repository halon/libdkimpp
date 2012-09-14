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
#ifndef _DKIM_RESOLVER_HPP_
#define _DKIM_RESOLVER_HPP_

#include <string>
#if defined __FreeBSD__ || __OpenBSD__
#include <netinet/in.h>
#include <arpa/nameser.h>
#endif
#include <resolv.h>

namespace DKIM {
	namespace Util {
		class Resolver
		{
			public:
				Resolver();
				~Resolver();

				bool GetTXT(const std::string& domain, std::string& result);
			private:
				struct __res_state m_res;	
		};
	}
}

#endif
