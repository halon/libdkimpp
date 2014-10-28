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
#include "Tokenizer.hpp"
#include "Util.hpp"

#include "QuotedPrintable.hpp"
#include "Base64.hpp"

#include <stdio.h>

using namespace DKIM::Tokenizer;
using DKIM::Util::StringFormat;

std::string DKIM::Tokenizer::ReadWhiteSpace(std::istream& stream, WhiteSpaceType type)
	throw (DKIM::PermanentError)
{
	switch(type)
	{
		case READ_CRLF:
			{
				std::string _s;
				if (stream.peek() == '\r')
				{
					_s += (char)stream.get(); // read '\r'

					if (stream.peek() != '\n')
						throw DKIM::PermanentError(StringFormat("CR without matching LF, 0x%x at position %zu",
									stream.peek(),
									(size_t)stream.tellg()
									)
								);

					_s += (char)stream.get(); // read '\n'
					return _s;
				}
				return "";
			}
			break;
			/**
			 * Skip any number of ' ' and '\t' followed by each other
			 */
		case READ_WSP:
			{
				std::string _s;
				if (stream.peek() == ' ' || stream.peek() == '\t')
				{
					_s += (char)stream.get(); // discard wsp
					return _s;
				}
				return "";
			}
			break;
			/**
			 * Skip any number of WSP followed by CRLF and more than one WSP
			 */
		case READ_FWS:
			{
				std::string _s;
				std::string _t;

				while (!(_t = ReadWhiteSpace(stream, READ_WSP)).empty())
				{ _s += _t; }

				if ((_t = ReadWhiteSpace(stream, READ_CRLF)).empty())
					return _s;
				_s += _t;

				if ((_t = ReadWhiteSpace(stream, READ_WSP)).empty())
					goto unwind;
				_s += _t;

				while (!(_t = ReadWhiteSpace(stream, READ_WSP)).empty())
				{ _s += _t; }

				return _s;
unwind:
				stream.clear();
				for (size_t i = _s.size(); i > 0; i--)
				{
					stream.putback(_s[i-1]);
				}
				return "";
			}
			break;
	}

	// not-reached
	return "";
}

std::list<std::string> DKIM::Tokenizer::ValueList(const std::string& input)
	throw (DKIM::PermanentError)
{
	std::list<std::string> values;

	std::stringstream data(input);
		
	while (true)
	{
		std::string value;

		// [ FWS ]
		while (!ReadWhiteSpace(data, READ_FWS).empty());

		// ...
		if (data.peek() == EOF) break;

		// tag-value
		std::string value_buf;
		while (true)
		{
			std::string ws = ReadWhiteSpace(data, READ_FWS);
			if (ws.empty())
			{
				if (data.peek() == ':' || data.peek() == EOF )
					break;

				if (!value_buf.empty())
				{
					value += value_buf;
					value_buf = "";
				}

				value += (char)data.get();
			}

			value_buf += ws;
		}

		if (value.empty())
			throw DKIM::PermanentError(StringFormat("Invalid list value (empty), expecting value at position %zu",
						(size_t)data.tellg()
						)
					);

		values.push_back(value);

		// [ ':' ]
		if (data.get() == EOF) break;
	}

	return values;
}

DKIM::Tokenizer::AddressListTokens DKIM::Tokenizer::NextAddressListToken(std::stringstream& data, std::string& token)
	throw (DKIM::PermanentError)
{
	token.clear();

	while (data.peek() != EOF)
	{
		if (!ReadWhiteSpace(data, READ_FWS).empty())
		{
			if (!token.empty())
				break;
		}
		if (data.peek() == '"')
		{
			if (!token.empty()) return TOK_ATOM;
			data.get();
			while (true)
			{
				char c = (char)data.get();

				if (c == EOF) {
					throw DKIM::PermanentError("unclosed string");
				} else if (c == '\\') {
					if (data.peek() == EOF)
						throw DKIM::PermanentError("incomplete escape sequence");
					// rfc822: However, quoting is PERMITTED for any character.
					//if (data.peek() != '"')
					//	throw DKIM::PermanentError("bad escape sequence");
					token += (char)data.get();
				} else if (c == '"') {
					break;
				} else {
					token += c;
				}
			}
			return TOK_QUOTED;
		}
		if (data.peek() == '(')
		{
			if (!token.empty()) return TOK_ATOM;
			data.get(); // throw away (
			int depth = 1;
			while (depth != 0)
			{
				if (data.peek() == EOF)
					throw DKIM::PermanentError("unclosed comment");
				if (data.peek() == '\\')
				{
					data.get();
					if (data.peek() == EOF)
						throw DKIM::PermanentError("incomplete escape sequence");
					// rfc822: However, quoting is PERMITTED for any character.
					//if (data.peek() != ')' && data.peek() != '(')
					//	throw DKIM::PermanentError("unclosed comment");
					token += (char)data.get();
				}
				if (data.peek() == '(')
					++depth;
				if (data.peek() == ')')
					--depth;
				if (depth > 0)
					token += (char)data.get();
				else
					data.get();
			}
			// eat until )
			return TOK_COMMENT;
		}
		if (data.peek() == '<')
		{
			if (!token.empty()) return TOK_ATOM;
			data.get();
			return TOK_TAG_OPEN;
		}
		if (data.peek() == '>')
		{
			if (!token.empty()) return TOK_ATOM;
			data.get();
			return TOK_TAG_CLOSE;
		}
		if (data.peek() == ',' || data.peek() == ';')
		{
			if (!token.empty()) return TOK_ATOM;
			data.get();
			return TOK_SEPARATOR;
		}
		token += (char)data.get();
	}

	if (!token.empty()) return TOK_ATOM;
	return TOK_EOF;
}

std::list<std::string> DKIM::Tokenizer::ParseAddressList(const std::string& input)
	throw (DKIM::PermanentError)
{
	std::list<std::string> list;

	std::stringstream data(input);
	std::string token;

	AddressListTokens lasttype = TOK_SEPARATOR, type = TOK_SEPARATOR;

	std::list<std::string> tokens;
	bool inOpentag = false;
	while (type != TOK_EOF)
	{
		lasttype = type;
		type = NextAddressListToken(data, token);

		switch(type)
		{
			case TOK_QUOTED:
				tokens.push_back(token);
			break;
			case TOK_ATOM:
				tokens.push_back(token);
			break;
			case TOK_COMMENT:
				// ignore comments
			break;
			case TOK_TAG_OPEN:
				tokens.clear();
				inOpentag = true;
			break;
			case TOK_TAG_CLOSE:
				inOpentag = false;
			case TOK_SEPARATOR:
			case TOK_EOF:
			{
				if (inOpentag == true)
				{
					throw DKIM::PermanentError("unclosed < addr-spec >");
				}

				if (tokens.empty()) break;

				// skip , in unescaped user parts like From: User, Company Inc <foo@example.org>
				if (type == TOK_SEPARATOR && lasttype != TOK_TAG_CLOSE && tokens.back().find('@') == std::string::npos)
				{
					tokens.clear();
					continue;
				}
				
				// do recrusive..
				if (lasttype == TOK_QUOTED && tokens.size() == 1)
				{
					std::list<std::string> addresses = ParseAddressList((*tokens.begin()));
					for (std::list<std::string>::const_iterator i = addresses.begin(); i != addresses.end(); ++i)
					{
						list.push_back(*i);
					}
				} else {
					std::string tmp;
					for (std::list<std::string>::const_iterator i = tokens.begin(); i != tokens.end(); ++i)
					{
						tmp += *i;
					}
					list.push_back(tmp);
				}
				tokens.clear();
			}
			break;
		}
	}

	return list;
}
