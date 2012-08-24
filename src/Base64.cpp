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
#include "Base64.hpp"

#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/buffer.h>

using DKIM::Conversion::Base64;

std::string Base64::Decode(const std::string& data)
	throw (DKIM::PermanentError)
{
	BIO *i, *o, *l;
	i = BIO_new(BIO_f_base64());
	BIO_set_flags(i, BIO_FLAGS_BASE64_NO_NL);
	o = BIO_new(BIO_s_mem());
	l = BIO_push(i, o);
	BIO_write(o, data.c_str(), data.size());
	BIO_flush(o);

	char b[1024];
	int r;
	std::string result;
	while ((r = BIO_read(l, b, sizeof(b))) > 0)
	{
		result.append(b, r);
	}

	BIO_free_all(l);
	return result;
}

std::string Base64::Encode(const std::string& data)
	throw (DKIM::PermanentError)
{
	BIO *i, *o, *l;
	i = BIO_new(BIO_f_base64());
	o = BIO_new(BIO_s_mem());
	l = BIO_push(i, o);
	BIO_set_flags(l, BIO_FLAGS_BASE64_NO_NL);
	BIO_write(l, data.c_str(), data.size());
	BIO_flush(l);
	std::string str;

	char buf[256];
	int r;
	while ((r = BIO_read(o, buf, sizeof(buf))) > 0)
	{
		if (buf[r - 1] == '\n') --r;
		str.append(buf, r);
	}

	BIO_free_all(l);
	return str;
}
