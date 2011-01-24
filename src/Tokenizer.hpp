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
#ifndef _DKIM_TOKENIZER_HPP_
#define _DKIM_TOKENIZER_HPP_

#include "Exception.hpp"

#include <string>
#include <list>
#include <iostream>
#include <sstream>

namespace DKIM {
	namespace Tokenizer {
		typedef enum {
			READ_CRLF,
			READ_WSP,
			READ_FWS
		} WhiteSpaceType;

		std::string ReadWhiteSpace(std::istream& stream, WhiteSpaceType type)
			throw (DKIM::PermanentError);

		std::list<std::string> ValueList(const std::string& input)
			throw (DKIM::PermanentError);

		typedef enum {
			TOK_QUOTED,
			TOK_ATOM,
			TOK_COMMENT,
			TOK_TAG_OPEN,
			TOK_TAG_CLOSE,
			TOK_SEPARATOR,
			TOK_EOF
		} AddressListTokens;

		AddressListTokens NextAddressListToken(std::stringstream& data, std::string& token)
			throw (DKIM::PermanentError);

		std::list<std::string> ParseAddressList(const std::string& input)
			throw (DKIM::PermanentError);
	}
}

#endif
