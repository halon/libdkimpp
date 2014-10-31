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
#ifndef _DKIM_SIGNATURE_HPP_
#define _DKIM_SIGNATURE_HPP_

#include "DKIM.hpp"
#include "TagList.hpp"

#include <string>
#include <list>
#include <stdexcept>

namespace DKIM
{
	class Signature
	{
		public:
			typedef enum { DKIM_Q_DNSTXT } QueryType;

			Signature()
			: m_bodySize(0), m_bodySizeLimit(false)
			{ Reset(); }

			void Reset();
			void Parse(const std::string& signature) throw (DKIM::PermanentError);

			bool GetTag(const std::string& name, TagListEntry& tag) const
			{ return m_tagList.GetTag(name, tag); }

			// Get Functions

			Algorithm GetAlgorithm() const
			{ return m_algorithm; }

			const std::string& GetSignatureData() const
			{ return m_b; }

			const std::string& GetBodyHash() const
			{ return m_bh; }

			CanonMode GetCanonModeHeader() const
			{ return m_header; }

			CanonMode GetCanonModeBody() const
			{ return m_body; }

			const std::string& GetDomain() const
			{ return m_domain; }

			const std::list<std::string>& GetSignedHeaders() const
			{ return m_headers; }

			const std::string& GetMailLocalPart() const
			{ return m_mailLocalPart; }

			const std::string& GetMailDomain() const
			{ return m_mailDomain; }

			unsigned long GetBodySize() const
			{ return m_bodySize; }

			bool GetBodySizeLimit() const
			{ return m_bodySizeLimit; }

			QueryType GetQueryType() const
			{ return m_queryType; }

			const std::string& GetSelector() const
			{ return m_selector; }

		private:
			TagList m_tagList;

			Algorithm m_algorithm;
			std::string m_b;
			std::string m_bh;
			CanonMode m_header;
			CanonMode m_body;
			std::string m_domain;
			std::list<std::string> m_headers;
			std::string m_mailLocalPart;
			std::string m_mailDomain;
			unsigned long m_bodySize;
			bool m_bodySizeLimit;
			QueryType m_queryType;
			std::string m_selector;
	};
}

#endif
