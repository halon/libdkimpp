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
#include "Util.hpp"

#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>

std::string DKIM::Util::CanonMode2String(CanonMode mode)
{
	switch (mode)
	{
		case DKIM::DKIM_C_SIMPLE:
			return "simple";
		case DKIM::DKIM_C_RELAXED:
			return "relaxed";
	}
	return "unknown";
}

std::string DKIM::Util::Algorithm2String(SignatureAlgorithm signatureAlgorithm, Algorithm algorithm)
{
	std::string alg;
	switch (signatureAlgorithm)
	{
		case DKIM::DKIM_SA_RSA:
			alg += "rsa";
		break;
		case DKIM::DKIM_SA_ED25519:
			alg += "ed25519";
		break;
	}
	alg += "-";
	switch (algorithm)
	{
		case DKIM::DKIM_A_SHA1:
			alg += "sha1";
		break;
		case DKIM::DKIM_A_SHA256:
			alg += "sha256";
		break;
	}
	return alg;
}

std::string DKIM::Util::StringFormat(const char* fmt, ...)
{
	va_list args;
	va_start(args, fmt);
	char* mem = NULL;
	if (vasprintf(&mem, fmt, args) == -1)
		throw std::bad_alloc();
	std::string result = mem;
	free(mem);
	va_end(args);
	return result;
}

static std::string alphanum =
	"abcdefghijklmnopqrstuvwxyz"
	"ABCDEFGHIJKLMNOPQRSTUVWXYZ"
	"0123456789";

bool ValidateSubDomain(const std::string& subdomain)
{
	if (subdomain.empty())
		return false;

	if (alphanum.find(*subdomain.begin()) == std::string::npos)
		return false;

	if (alphanum.find(*subdomain.rbegin()) == std::string::npos)
		return false;

	if (subdomain.find_first_not_of(alphanum + "-") != std::string::npos)
		return false;

	return true;
}

bool DKIM::Util::ValidateDomain(const std::string& domain)
{
	size_t pos = std::string::npos, lpos = 0;
	while ((pos = domain.find('.', lpos)) != std::string::npos)
	{
		if (!ValidateSubDomain(domain.substr(lpos, pos - lpos)))
			return false;

		lpos = pos + 1;
	}

	return ValidateSubDomain(domain.substr(lpos));
}
