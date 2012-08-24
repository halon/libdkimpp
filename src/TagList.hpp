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
#ifndef _DKIM_TAGLIST_HPP_
#define _DKIM_TAGLIST_HPP_

#include "Exception.hpp"

#include <string>
#include <map>
#include <iostream>

namespace DKIM {
	class TagListEntry
	{
		public:
			/* Set */
			void SetValue(const std::string& value)
			{ m_value = value; }
			void SetValueOffset(const std::streamoff& offset)
			{ m_valueOffset = offset; }

			/* Get */
			const std::string& GetValue() const
			{ return m_value; }
			std::streamoff GetValueOffset() const
			{ return m_valueOffset; }
		private:
			std::string m_value;
			std::streamoff m_valueOffset;
	};
	class TagList
	{
		public:
			void Reset();

			void Parse(const std::string& input)
				throw (DKIM::PermanentError);

			bool GetTag(const std::string& name, TagListEntry& tag) const;
		private:
			std::map<std::string, TagListEntry> m_tags;
	};
}

#endif
