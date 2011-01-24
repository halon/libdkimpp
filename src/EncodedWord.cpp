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
#include "EncodedWord.hpp"
#include "Tokenizer.hpp"

#include "QuotedPrintable.hpp"
#include "Base64.hpp"

#include <stdio.h>

using DKIM::Conversion::EncodedWord;
using namespace DKIM::Tokenizer;

std::string EncodedWord::Decode(const std::string& input)
	throw (DKIM::PermanentError)
{
	std::string output;
	std::stringstream data(input);

	// [ FWS ]
	while(!ReadWhiteSpace(data, READ_FWS).empty());

	std::string ws;
	while ( true )
	{
		while ( true )
		{
			std::string w = ReadWhiteSpace(data, READ_WSP);
			if (!w.empty())
			{
				ws += w;
				continue;
			}
			w = ReadWhiteSpace(data, READ_CRLF);
			if (!w.empty())
			{
				continue;
			}
			break;
		}

		// something in the buffer to be read...
		if (data.peek() == '=')
		{
			std::string buffer;
			buffer = (char)data.get();

			std::string charset;
			std::string encoding;
			std::string encdata;

			bool fail = false;
			if (!fail && data.peek() == '?')
			{
				buffer += (char)data.get();
				while( ! fail )
				{
					if (data.peek() == EOF) { fail = true; break; }
					if (data.peek() == '?')
						break;
					else
						charset += (char)data.get();
				}
				buffer += charset;
			} else fail = true;
			if (!fail && data.peek() == '?')
			{
				buffer += (char)data.get();
				while( ! fail )
				{
					if (data.peek() == EOF) { fail = true; break; }
					if (data.peek() == '?')
						break;
					else
						encoding += (char)data.get();
				}
				buffer += encoding;
			} else fail = true;
			if (!fail && data.peek() == '?')
			{
				buffer += (char)data.get();
				while( ! fail )
				{
					if (data.peek() == EOF) { fail = true; break; }
					if (data.peek() == '?')
						break;
					else
						encdata += (char)data.get();
				}
				buffer += encdata;
			} else fail = true;
			if (!fail && data.peek() == '?')
			{
				buffer += (char)data.get();
				if (data.peek() == '=')
				{
					buffer += (char)data.get();
				} else fail = true;
			} else fail = true;
			if (!fail && data.peek() != EOF && data.peek() != ' ' && data.peek() != '\r' && data.peek() != '\n' && data.peek() != '\t')
			{
				fail = true;
			}

			while (!fail) {
				try {
					if (encoding == "q" || encoding == "Q")
					{
						encdata = DKIM::Conversion::QuotedPrintable::Decode(encdata, true);
						break;
					}
					if (encoding == "b" || encoding == "B")
					{
						encdata = DKIM::Conversion::Base64::Decode(encdata);
						break;
					}
				} catch(...) {
				}
				fail = true;
			} while ( false );

			if (!fail)
			{
				output += encdata;
			} else {
				output += ws + buffer;
			}
			ws.clear();
		} else {
			if (data.peek() == EOF)
			{
				break;
			}
			output += ws;
			ws.clear();
			output += (char)data.get();
		}
	}

	return output;
}
