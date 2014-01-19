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
#include "ADSP.hpp"

using DKIM::ADSP;

ADSP::ADSP()
: m_result(DKIM_ADSP_TEMPERROR)
{
}

ADSP::~ADSP()
{
}

void ADSP::SetResult(const ADSP::ADSPResult& result, const std::string& reason)
{
	m_result = result;
	m_reason = reason;
}

ADSP::ADSPResult ADSP::GetResult() const
{
	return m_result;
}

/*

   Code:     none

   Meaning:  No DKIM Author Domain Signing Practices (ADSP) record was
             published.

   Code:     pass

   Meaning:  This message had an Author Domain Signature that was
             validated.  (An ADSP check is not strictly required to be
             performed for this result since a valid Author Domain
             Signature satisfies all possible ADSP policies.)

   Code:     unknown

   Meaning:  No valid Author Domain Signature was found on the message
             and the published ADSP was "unknown".

   Code:     fail

   Meaning:  No valid Author Domain Signature was found on the message
             and the published ADSP was "all".

   Code:     discard

   Meaning:  No valid Author Domain Signature was found on the message
             and the published ADSP was "discardable".

   Code:     nxdomain

   Meaning:  Evaluating the ADSP for the Author's DNS domain indicated
             that the Author's DNS domain does not exist.

   Code:     temperror

   Meaning:  An ADSP record could not be retrieved due to some error
             that is likely transient in nature, such as a temporary DNS
             error.  A later attempt may produce a final result.

   Code:     permerror

   Meaning:  An ADSP record could not be retrieved due to some error
             that is likely not transient in nature, such as a permanent
             DNS error.  A later attempt is unlikely to produce a final
             result.
*/

std::string ADSP::GetResultAsString() const
{
	switch(m_result)
	{
		case DKIM_ADSP_NONE:
			return "none";
		case DKIM_ADSP_PASS:
			return "pass";
		case DKIM_ADSP_UNKNOWN:
			return "unknown";
		case DKIM_ADSP_FAIL:
			return "fail";
		case DKIM_ADSP_DISCARD:
			return "discard";
		case DKIM_ADSP_NXDOMAIN:
			return "nxdomain";
		case DKIM_ADSP_TEMPERROR:
			return "temperror";
		case DKIM_ADSP_PERMERROR:
			return "permerror";
	}
	return "unknown";
}

const std::string& ADSP::GetReason() const
{
	return m_reason;
}

const std::string& ADSP::GetDomain() const
{
	return m_domain;
}

void ADSP::SetDomain(const std::string& domain)
{
	m_domain = domain;
}
