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
#ifndef _DKIM_EXCEPTION_HPP_
#define _DKIM_EXCEPTION_HPP_

#include <stdexcept>

namespace DKIM
{
	enum AR_CLASS {
		AR_NONE,
		AR_PASS,
		AR_FAIL,
		AR_POLICY,
		AR_NEUTRAL,
		AR_TEMPERROR,
		AR_PERMERROR,
	};
	class PermanentError : public std::runtime_error {
		public:
			PermanentError(std::string const& msg, AR_CLASS ar_class_ = AR_CLASS::AR_PERMERROR):
				std::runtime_error(msg),
				ar_class(ar_class_)
			{}
			const char* getAuthenticationResult()
			{
				switch (ar_class)
				{
					case AR_NONE: return "none";
					case AR_PASS: return "pass";
					case AR_FAIL: return "fail";
					case AR_POLICY: return "policy";
					case AR_NEUTRAL: return "neutral";
					case AR_TEMPERROR: return "temperror";
					case AR_PERMERROR: return "permerror";
				}
				return "permerror";
			}
		private:
			AR_CLASS ar_class;
	};
	class TemporaryError : public std::runtime_error {
		public:
			TemporaryError(std::string const& msg, AR_CLASS ar_class_ = AR_CLASS::AR_TEMPERROR):
				std::runtime_error(msg),
				ar_class(ar_class_)
			{}
			const char* getAuthenticationResult()
			{
				switch (ar_class)
				{
					case AR_NONE: return "none";
					case AR_PASS: return "pass";
					case AR_FAIL: return "fail";
					case AR_POLICY: return "policy";
					case AR_NEUTRAL: return "neutral";
					case AR_TEMPERROR: return "temperror";
					case AR_PERMERROR: return "permerror";
				}
				return "permerror";
			}
		private:
			AR_CLASS ar_class;
	};
}

#endif
