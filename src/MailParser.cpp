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
#include "MailParser.hpp"

using DKIM::Header;
using DKIM::Message;

Header::Header()
: m_valueOffset(0)
{
}

Header::~Header()
{
}

bool Header::ParseLine(const std::string& data)
{
	if (!m_header.empty())
		m_header += "\r\n";

	m_header += data;

	if (m_valueOffset == 0)
	{
		size_t sep = m_header.find(":");
		if (sep == std::string::npos)
			return false;

		m_valueOffset = sep + 1;

		m_name = m_header.substr(0, sep);
		m_name.erase(0, m_name.find_first_not_of(" \t"));
		m_name.erase(m_name.find_last_not_of(" \t") + 1);
	}
	return true;
}

const std::string& Header::GetName() const
{
	return m_name;
}

const std::string& Header::GetHeader() const
{
	return m_header;
}

void Header::SetStart(std::streamoff hStart)
{
	headerStart = hStart;
}

void Header::SetEnd(std::streamoff hEnd)
{
	headerEnd = hEnd;
}

std::streamoff Header::GetStart() const { return headerStart; }
std::streamoff Header::GetEnd() const { return headerEnd; }

Message::Message()
{
	Reset();
}

void Message::Reset()
{
	m_done = false;
	m_tmpHeader.reset();
	m_header.clear();
	m_bodyOffset = 0;
}

bool Message::IsDone() const
{
	return m_done;
}

bool Message::ParseLine(std::istream& stream, bool doubleDots)
{
	std::streamoff startPos = stream.tellg();

	std::string line;
	if (!std::getline(stream, line))
	{
		if (m_tmpHeader.get())
			m_header.push_back(m_tmpHeader);

		m_bodyOffset = -1;
		m_done = true;
		return false;
	}

	// double dots (postfix file may have .., instead of .)
	if (doubleDots && line.substr(0, 2) == "..")
	{
		line.erase(0, 1);
	}

	// remove possible \r (if not removed by getline *probably not*)
	if (line.size() > 0 && line[line.size()-1] == '\r')
		line.erase(line.size()-1);

	if (line.size() == 0)
	{
		if (m_tmpHeader.get())
			m_header.push_back(m_tmpHeader);
		m_tmpHeader.reset();

		m_bodyOffset = stream.tellg();
		m_done = true;

		return true;
	}

	if (line[0] != '\t' && line[0] != ' ')
	{
		if (m_tmpHeader.get())
			m_header.push_back(m_tmpHeader);
		m_tmpHeader.reset(new Header());
		m_tmpHeader->SetStart(startPos);
	}

	if (!m_tmpHeader.get())
		m_tmpHeader.reset(new Header());
	m_tmpHeader->ParseLine(line);
	m_tmpHeader->SetEnd(stream.tellg());

	return true;
}

const std::list<std::shared_ptr<Header> >& Message::GetHeaders() const
{
	return m_header;
}

std::streamoff Message::GetBodyOffset() const
{
	return m_bodyOffset;
}
