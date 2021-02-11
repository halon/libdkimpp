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
#include "QuotedPrintable.hpp"
#include "Tokenizer.hpp"
#include "Util.hpp"
#include "Exception.hpp"

#include <sstream>
#include <cstdio>
#include <cstdlib>

using DKIM::Conversion::QuotedPrintable;
using DKIM::Tokenizer::ReadWhiteSpace;
using DKIM::Util::StringFormat;

std::string QuotedPrintable::Decode(const std::string& input, bool convert_to_space)
{
	std::stringstream data(input);
	std::string output;

	while (true)
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
				throw DKIM::PermanentError(StringFormat("Quoted-printable decoding failed; unexpected 0x%x, expecting HEX at position %ld",
							data.peek() & 0xff,
							(ssize_t)data.tellg()
							)
						);

			if ((data.peek() >= 'A' && data.peek() <= 'F') || (data.peek() >= '0' && data.peek() <= '9'))
				hex += (char)data.get();
			else
				throw DKIM::PermanentError(StringFormat("Quoted-printable decoding failed; unexpected 0x%x, expecting HEX at position %ld",
							data.peek() & 0xff,
							(ssize_t)data.tellg()
							)
						);

			output += (char)strtol(hex.c_str(), nullptr, 16);
		} else if (
					(data.peek() >= '\x21' && data.peek() <= '\x3A') ||
					(data.peek() == '\x3C') ||
					(data.peek() >= '\x3E' && data.peek() <= '\x7E')
				) {
			output += (char)data.get();
		} else if (!ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS).empty()) {
			//
		} else {
			throw DKIM::PermanentError(StringFormat("Quoted-printable decoding failed; unsafe character 0x%x at position %ld",
						data.peek() & 0xff,
						(ssize_t)data.tellg()
						)
					);
		}
	}

	return output;
}

/*
 * Following the special rules of DKIM-Quoted-Printable
 */
std::string QuotedPrintable::Encode(const std::string& input)
{
	static unsigned long qp_table[256] = {
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0x00 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0x10 */
		3, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x20 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, 1, 3, 1, 1, /* 0x30 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x40 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x50 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, /* 0x60 */
		1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 1, 3, /* 0x70 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0x80 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0x90 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xA0 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xB0 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xC0 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xD0 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, /* 0xE0 */
		3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3, 3 /* 0xF0 */
	};
	size_t len = 0;
	for (char i : input)
		len += qp_table[(unsigned char)i];
	std::string result;
	result.reserve(len);
	for (char i : input)
	{
		if (qp_table[(unsigned char)i] == 1)
			result += i;
		else {
			static char qp_digits[] = "0123456789ABCDEF";
			result += "=";
			result += qp_digits[(i >> 4) & 0x0f];
			result += qp_digits[(i & 0x0f)];
		}
	}
	return result;
}
