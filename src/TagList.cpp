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
#include "TagList.hpp"
#include "Tokenizer.hpp"
#include "Util.hpp"
#include "Exception.hpp"

using DKIM::TagList;
using DKIM::Tokenizer::ReadWhiteSpace;
using DKIM::Util::StringFormat;

/*

 3.2.  Tag=Value Lists

   DKIM uses a simple "tag=value" syntax in several contexts, including
   in messages and domain signature records.

   Values are a series of strings containing either plain text, "base64"
   text (as defined in [RFC2045], Section 6.8), "qp-section" (ibid,
   Section 6.7), or "dkim-quoted-printable" (as defined in Section 2.6).
   The name of the tag will determine the encoding of each value.
   Unencoded semicolon (";") characters MUST NOT occur in the tag value,
   since that separates tag-specs.

      INFORMATIVE IMPLEMENTATION NOTE: Although the "plain text" defined
      below (as "tag-value") only includes 7-bit characters, an
      implementation that wished to anticipate future standards would be
      advised not to preclude the use of UTF8-encoded text in tag=value
      lists.

   Formally, the syntax rules are as follows:

        tag-list  =  tag-spec 0*( ";" tag-spec ) [ ";" ]
        tag-spec  =  [FWS] tag-name [FWS] "=" [FWS] tag-value [FWS]
        tag-name  =  ALPHA 0*ALNUMPUNC
        tag-value =  [ tval 0*( 1*(WSP / FWS) tval ) ]
                          ; WSP and FWS prohibited at beginning and end
        tval      =  1*VALCHAR
        VALCHAR   =  %x21-3A / %x3C-7E
                          ; EXCLAMATION to TILDE except SEMICOLON
        ALNUMPUNC =  ALPHA / DIGIT / "_"

   Note that WSP is allowed anywhere around tags.  In particular, any
   WSP after the "=" and any WSP before the terminating ";" is not part
   of the value; however, WSP inside the value is significant.

   Tags MUST be interpreted in a case-sensitive manner.  Values MUST be
   processed as case sensitive unless the specific tag description of
   semantics specifies case insensitivity.

   Tags with duplicate names MUST NOT occur within a single tag-list; if
   a tag name does occur more than once, the entire tag-list is invalid.

   Whitespace within a value MUST be retained unless explicitly excluded
   by the specific tag description.

   Tag=value pairs that represent the default value MAY be included to
   aid legibility.

   Unrecognized tags MUST be ignored.

   Tags that have an empty value are not the same as omitted tags.  An
   omitted tag is treated as having the default value; a tag with an
   empty value explicitly designates the empty string as the value.  For
   example, "g=" does not mean "g=*", even though "g=*" is the default
   for that tag.

*/

#include <sstream>
#include <cstdio>

void TagList::Reset()
{
	m_tags.clear();
}

void TagList::Parse(const std::string& input)
{
	std::stringstream data(input);

	while (true)
	{
		std::string name;
		std::string value;

		// [ FWS ]
		while (!ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS).empty());

		// ...
		if (data.peek() == EOF) break;

		// tag-name
		if (
				(data.peek() >= 'A' && data.peek() <= 'Z') ||
				(data.peek() >= 'a' && data.peek() <= 'z') ||
				(data.peek() >= '0' && data.peek() <= '9')
		   ) {
			name += (char)data.get();
		}
		while (
				(data.peek() >= 'A' && data.peek() <= 'Z') ||
				(data.peek() >= 'a' && data.peek() <= 'z') ||
				(data.peek() >= '0' && data.peek() <= '9') ||
				(data.peek() == '_')
			 ) {
			name += (char)data.get();
		}

		if (name.empty())
			throw DKIM::PermanentError(StringFormat("Invalid tag name (empty), expecting name at position %ld",
						(ssize_t)data.tellg()
						)
					);
		if (m_tags.find(name) != m_tags.end())
			throw DKIM::PermanentError(StringFormat("Duplicate tag name (%s)",
							name.c_str()
						)
					);

		// [ FWS ]
		while (!ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS).empty());

		// =
		if (data.peek() != '=')
			throw DKIM::PermanentError(StringFormat("Invalid tag list; unexpected 0x%x, expecting = at position %zu",
							data.peek(),
							(size_t)data.tellg()	
						)
					);
		else
			data.get(); // discard '='

		// [ FWS ]
		while (!ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS).empty());

		TagListEntry tagEntry;
		tagEntry.SetValueOffset(data.tellg());

		// tag-value
		std::string value_buf;
		while (data.peek() != ';' && data.peek() != EOF)
		{
			if (
					(data.peek() >= '\x21' && data.peek() <= '\x3A') ||
					(data.peek() >= '\x3C' && data.peek() <= '\x7E')
			   ) {
				if (!value_buf.empty())
				{
					value += value_buf;
					value_buf = "";
				}

				value += (char)data.get();
				continue;
			}

			std::string ws = ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS);
			if (ws.empty())
				throw DKIM::PermanentError(StringFormat("Invalid tag value (invalid data), unexpected 0x%x at position %ld",
							data.peek() & 0xff,
							(ssize_t)data.tellg()
							)
						);

			value_buf += ws;
		}

		// save
		tagEntry.SetValue(value);
		m_tags[name] = tagEntry;

		// [ ';' ]
		if (data.get() == EOF) break;
	}

	return;
}

bool TagList::GetTag(const std::string& name, TagListEntry& tag) const
{
	std::map<std::string, TagListEntry>::const_iterator i = m_tags.find(name);
	if (i == m_tags.end())
		return false;

	tag = i->second;
	return true;
}
