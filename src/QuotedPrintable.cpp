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
#include "QuotedPrintable.hpp"
#include "Tokenizer.hpp"
#include "Util.hpp"

#include <sstream>
#include <stdio.h>
#include <stdlib.h>

using DKIM::Conversion::QuotedPrintable;
using DKIM::Tokenizer::ReadWhiteSpace;
using DKIM::Util::StringFormat;

std::string QuotedPrintable::Decode(const std::string& input, bool convert_to_space)
	throw (DKIM::PermanentError)
{
	std::stringstream data(input);
	std::string output;

	while ( true )
	{
		if (data.peek() == EOF) break;

		if (convert_to_space && data.peek() == '_')
		{
			data.get();
			output += " ";
			continue;
		}

		if (data.peek() == '=')
		{
			data.get(); // '='
		
			std::string hex;
			if ((data.peek() >= 'A' && data.peek() <= 'F') || (data.peek() >= '0' && data.peek() <= '9'))
				hex += (char)data.get();
			else
				throw DKIM::PermanentError(StringFormat("Quoted-printable decoding failed; unexpected 0x%x, expecting HEX at position %d",
							data.peek(),
							(size_t)data.tellg()	
							)
						);

			if ((data.peek() >= 'A' && data.peek() <= 'F') || (data.peek() >= '0' && data.peek() <= '9'))
				hex += (char)data.get();
			else
				throw DKIM::PermanentError(StringFormat("Quoted-printable decoding failed; unexpected 0x%x, expecting HEX at position %d",
							data.peek(),
							(size_t)data.tellg()	
							)
						);

			output += (char)strtol(hex.c_str(), NULL, 16);
		} else if (
					(data.peek() >= '\x21' && data.peek() <= '\x3A') ||
					(data.peek() == '\x3C') ||
					(data.peek() >= '\x3E' && data.peek() <= '\x7E')
				) {
			output += (char)data.get();
		} else if (!ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS).empty()) {
			//
		} else {
			throw DKIM::PermanentError(StringFormat("Quoted-printable decoding failed; unsafe character 0x%x at position %d",
						data.peek(),
						(size_t)data.tellg()	
						)
					);
		}	
	}

	return output;
}
