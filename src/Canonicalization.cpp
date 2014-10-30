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
#include "Canonicalization.hpp"
#include "Tokenizer.hpp"
#include "Util.hpp"

#include <sstream>
#include <stdio.h>
#include <algorithm>

using DKIM::Conversion::CanonicalizationHeader;
using DKIM::Tokenizer::ReadWhiteSpace;
using DKIM::Util::StringFormat;

CanonicalizationHeader::CanonicalizationHeader(CanonMode type)
: m_type(type)
{
}

void CanonicalizationHeader::SetType(CanonMode type)
{
	m_type = type;
}

std::string CanonicalizationHeader::FilterHeader(const std::string& input) const
{
	if (m_type == DKIM_C_SIMPLE)
		return input;
	std::string output = input;

	/**
	 * The "relaxed" header canonicalization algorithm MUST apply the
	 * following steps in order:
	 */

	/**
	 * Convert all header field names (not the header field values) to
	 * lowercase.  For example, convert "SUBJect: AbC" to "subject: AbC".
	 */

	std::string::iterator colon = std::find(output.begin(), output.end(), ':');
	if (colon == output.end())
		throw DKIM::PermanentError(StringFormat("Header field %s is missing the colon separator",
					input.c_str()
					)
				);
	transform(output.begin(), colon, output.begin(), tolower);
	
	/**
	 * Unfold all header field continuation lines as described in
	 * [RFC2822]; in particular, lines with terminators embedded in
	 * continued header field values (that is, CRLF sequences followed by
	 * WSP) MUST be interpreted without the CRLF.  Implementations MUST
	 * NOT remove the CRLF at the end of the header field value.
	 *
	 * Convert all sequences of one or more WSP characters to a single SP
	 * character.  WSP characters here include those before and after a
	 * line folding boundary.
	 *
	 * Delete all WSP characters at the end of each unfolded header field
	 * value.
	 */

	std::stringstream data(output);

	std::string x;
	while (true)
	{
		bool found = false;
		while (!ReadWhiteSpace(data, DKIM::Tokenizer::READ_FWS).empty())
			found = true;

		if (data.peek() == EOF) break;

		if (found)
			x += " ";

		x += (char)data.get();
	}

	/**
	 * Delete any WSP characters remaining before and after the colon
	 * separating the header field name from the header field value.  The
	 * colon separator MUST be retained.
	 */

	size_t colonSplit = x.find(":");
	if (colonSplit == std::string::npos)
		throw DKIM::PermanentError(StringFormat("Header field %s is missing the colon separator",
					input.c_str()
					)
				);
	size_t colonAfter = x.find_first_not_of(" ", colonSplit + 1);
	if (colonAfter != std::string::npos)
		x.erase(colonSplit + 1, ( colonAfter - 1 ) - ( colonSplit ) );
	size_t colonBefore = x.substr(0, colonSplit ).find_last_not_of(" ");
	if (colonBefore != std::string::npos && colonBefore + 1 != colonSplit)
	{
		x.erase(colonBefore + 1, colonSplit - (colonBefore + 1) );
	}

	return x;
}

using DKIM::Conversion::CanonicalizationBody;

CanonicalizationBody::CanonicalizationBody(CanonMode type)
: m_type(type)
{
	Reset();
}

void CanonicalizationBody::SetType(CanonMode type)
{
	m_type = type;
}

void CanonicalizationBody::Reset()
{
	m_emptyLines = 0;	
	m_emptyBody = true;
}

size_t CanonicalizationBody::FilterLine(const std::string& input, std::vector<std::string>& output)
{
	std::string s = input;

	switch (m_type)
	{
		case DKIM_C_RELAXED:
		{
			/*
			   Ignores all whitespace at the end of lines.  Implementations MUST
			   NOT remove the CRLF at the end of the line.
			 */
			size_t wspEnd = s.find_last_not_of(" \t");
			if (wspEnd != std::string::npos)
				s.erase(wspEnd + 1);
			else
				s.clear();

			/*
			   Reduces all sequences of WSP within a line to a single SP
			   character.
			 */
			size_t nextWSP = 0;
			while ((nextWSP = s.find_first_of(" \t", nextWSP)) != std::string::npos)
			{
				size_t lastWSP = s.find_first_not_of(" \t", nextWSP);
				s.replace(nextWSP, lastWSP - nextWSP, " ");
				nextWSP++;
			}
		}
		break;
		case DKIM_C_SIMPLE:
		{
		}
		break;
	}

	/*
	   Ignores all empty lines at the end of the message body.  "Empty
	   line" is defined in Section 3.4.3.
	 */
	if (s.empty()) {
		++m_emptyLines;
		return 0;
	}

	m_emptyBody = false;

	for (; m_emptyLines; --m_emptyLines)
	{
		output.push_back("\r\n");
	}
	m_emptyLines = 1;

	output.push_back(s);
	return output.size();
}

size_t CanonicalizationBody::Done(std::vector<std::string>& output)
{
	// the rfc is unclear about this, but google does not insert an empty \r\n for
	// relaxed canonicalization...
	if (m_emptyBody == true && m_type == DKIM_C_RELAXED)
		return 0;

	output.push_back("\r\n");
	return output.size();
}
