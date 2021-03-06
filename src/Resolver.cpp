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
#include "Resolver.hpp"

#include <netinet/in.h>
#include <arpa/nameser.h>
#include <netdb.h>
#include <memory.h>

using DKIM::Util::Resolver;

/*
 * initialize thread-safe m_res structure
 */
Resolver::Resolver()
{
	memset(&m_res, 0, sizeof m_res);
#ifdef HAS_RES_NINIT
	res_ninit(&m_res);
#else
	res_init();
	m_res = _res;
#endif
}

/*
 * close thread-safe m_res structure
 */
Resolver::~Resolver()
{
#ifdef HAS_RES_NINIT
#ifdef __linux__
	res_nclose(&m_res); // nclose seems to be enough for cleanup on Linux
#else
	res_ndestroy(&m_res);
#endif
#else
	res_close();
#endif
}

/*
 * request for the T_TXT record of an domain name, if an error occures (false is returned)
 *  else true is returned (regardsless if the domain txt record exists or not)
 */
bool Resolver::GetTXT(const std::string& domain, std::string& result)
{
	unsigned char answer[64 * 1024];
	memset(answer, 0, sizeof answer);

#ifdef HAS_RES_NINIT
	int answer_length = res_nquery(&m_res, domain.c_str(), C_IN, T_TXT, answer, sizeof answer);
#else
	int answer_length = res_query(domain.c_str(), C_IN, T_TXT, answer, sizeof answer);
#endif

	// Resolve failed
	if (answer_length < 0)
	{
#ifdef HAS_RES_NINIT
		int err = m_res.res_h_errno;
#else
		int err = h_errno;
#endif
		// permanent errors
		if (err == NO_DATA)
			return true;
		if (err == HOST_NOT_FOUND)
			return true;
		if (err == NO_RECOVERY)
			return true;

		// TRY_AGAIN
		return false;
	}
	if (answer_length > (int)sizeof answer) {
		return false;
	}
	// from here on, we will only return true
	// because we got whatever response..

	// Skip header
	HEADER* header = (HEADER*)&answer;
	unsigned char* answerptr = answer + sizeof(HEADER);

	// Skip request query...
	int qc = ntohs((unsigned short)header->qdcount);
	int x, s;
	for (x = 0, s = dn_skipname(answerptr, answer + answer_length);
			x < qc && s >= 0;
			++x, s = dn_skipname(answerptr, answer + answer_length))
	{
		if (s >= 0)
			answerptr += s + QFIXEDSZ;
	}

	if (qc == x)
	{
		int cc = ntohs((unsigned short)header->ancount);
		for (int i = 0; i < cc; ++i)
		{
			if ((s=dn_skipname(answerptr, answer + answer_length)) < 0)
			{
				return true;
			}
			int t;
			answerptr += s;
			if (answerptr > answer + answer_length - (INT16SZ + INT16SZ + INT32SZ + INT16SZ))
			{
				return false;
			}
			GETSHORT(t, answerptr);
			answerptr += INT16SZ;
			answerptr += INT32SZ;
			GETSHORT(s, answerptr);
			if (answerptr + s < answer || answerptr + s > answer + answer_length)
			{
				return false;
			}
			switch (t)
			{
				case T_TXT:
					{
						const unsigned char* ptr = answerptr;
						size_t rec_len_left = s;

						while (rec_len_left > 0)
						{
							size_t txt_len = *ptr;
							if (txt_len >= rec_len_left)
								break;

							result.append((const char*)ptr + 1, txt_len);

							rec_len_left -= txt_len + 1;
							ptr += txt_len + 1;
						}
						answerptr += s;
					}
					break;
				default:
					// Skip eg. C_NAME
					answerptr += s;
			}
		}
		return true;
	}
	return true;
}
