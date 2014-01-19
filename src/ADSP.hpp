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
#ifndef _DKIM_ADSP_HPP_
#define _DKIM_ADSP_HPP_

#include "Exception.hpp"

namespace DKIM
{
	class ADSP
	{
		public:
			ADSP();
			~ADSP();

			typedef enum
			{
				DKIM_ADSP_NONE,
				DKIM_ADSP_PASS,
				DKIM_ADSP_UNKNOWN,
				DKIM_ADSP_FAIL,
				DKIM_ADSP_DISCARD,
				DKIM_ADSP_NXDOMAIN,
				DKIM_ADSP_TEMPERROR,
				DKIM_ADSP_PERMERROR
			} ADSPResult;

			ADSPResult GetResult() const;
			std::string GetResultAsString() const;
			const std::string& GetReason() const;
			void SetResult(const ADSPResult& result, const std::string& reason = "");

			const std::string& GetDomain() const;
			void SetDomain(const std::string& domain);
		private:
			ADSPResult m_result;
			std::string m_reason;

			std::string m_domain;
	};
}

#endif
