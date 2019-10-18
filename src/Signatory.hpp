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
#ifndef _DKIM_SIGNATORY_HPP_
#define _DKIM_SIGNATORY_HPP_

#include "Exception.hpp"
#include "DKIM.hpp"
#include "MailParser.hpp"
#include "Base64.hpp"
#include "SignatoryOptions.hpp"

#include <string>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/err.h>

namespace DKIM
{
	class Signatory
	{
		public:
			Signatory(std::istream& file);
			~Signatory();

			std::string CreateSignature(const SignatoryOptions& options);
		private:
			std::istream& m_file;
			DKIM::Message m_msg;
	};
}

#endif
