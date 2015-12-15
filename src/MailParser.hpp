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
#ifndef _DKIM_MAILPARSER_HPP_
#define _DKIM_MAILPARSER_HPP_

#include <stdio.h>
#include <stdlib.h>
#include <iostream>
#include <fstream>
#include <sstream>
#include <string>
#include <list>
#include <memory>

namespace DKIM
{
	class Header
	{
		public:
			Header();
			~Header();
			bool ParseLine(const std::string& data);
			const std::string& GetName() const;
			const std::string& GetHeader() const;

			size_t GetValueOffset() const
			{ return m_valueOffset; }
		private:
			std::string m_name;
			std::string m_header;
			size_t m_valueOffset;
	};
	class Message
	{
		public:
			typedef std::list<std::shared_ptr<Header> > HeaderList;
			Message();
			void Reset();
			bool IsDone() const;
			bool ParseLine(std::istream& stream, bool doubleDots = false);
			const HeaderList& GetHeaders() const;
			std::streamoff GetBodyOffset() const;
		private:
			std::shared_ptr<Header> m_tmpHeader;
			std::streamoff m_bodyOffset;

			HeaderList m_header;
			bool m_done;
	};
}

#endif
