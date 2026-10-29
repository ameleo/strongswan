/*
 * Copyright (C) 2026 Mickael Bourneuf
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the
 * Free Software Foundation; either version 2 of the License, or (at your
 * option) any later version.  See <http://www.fsf.org/copyleft/gpl.txt>.
 *
 * This program is distributed in the hope that it will be useful, but
 * WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
 * or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
 * for more details.
 */

#include "pkcs11_uri.h"

#include <ctype.h>
#include <errno.h>

#include <utils/debug.h>

typedef struct private_pkcs11_uri_t private_pkcs11_uri_t;

/**
 * Path attributes defined in RFC 7512, section 2.3
 */
typedef enum {
	URI_TOKEN,
	URI_MANUFACTURER,
	URI_SERIAL,
	URI_MODEL,
	URI_LIBRARY_MANUFACTURER,
	URI_LIBRARY_DESCRIPTION,
	URI_LIBRARY_VERSION,
	URI_SLOT_MANUFACTURER,
	URI_SLOT_DESCRIPTION,
	URI_SLOT_ID,
	URI_OBJECT,
	URI_TYPE,
	URI_ID,
	URI_ATTR_MAX,
} uri_attr_t;

/**
 * Names of the path attributes
 */
static const char *attr_names[] = {
	"token",
	"manufacturer",
	"serial",
	"model",
	"library-manufacturer",
	"library-description",
	"library-version",
	"slot-manufacturer",
	"slot-description",
	"slot-id",
	"object",
	"type",
	"id",
};

/**
 * Values of the type attribute
 */
static struct {
	const char *name;
	CK_OBJECT_CLASS class;
} types[] = {
	{ "cert",		CKO_CERTIFICATE		},
	{ "data",		CKO_DATA			},
	{ "private",	CKO_PRIVATE_KEY		},
	{ "public",		CKO_PUBLIC_KEY		},
	{ "secret-key",	CKO_SECRET_KEY		},
};

/**
 * Private data of a pkcs11_uri_t object.
 */
struct private_pkcs11_uri_t {

	/**
	 * Public interface.
	 */
	pkcs11_uri_t public;

	/**
	 * Whether a path attribute is set
	 */
	bool set[URI_ATTR_MAX];

	/**
	 * Decoded values of path attributes
	 */
	chunk_t values[URI_ATTR_MAX];

	/**
	 * Object class, if URI_TYPE is set
	 */
	CK_OBJECT_CLASS class;

	/**
	 * Library version, if URI_LIBRARY_VERSION is set
	 */
	CK_VERSION version;

	/**
	 * Slot ID, if URI_SLOT_ID is set
	 */
	CK_SLOT_ID slot;

	/**
	 * URI without query component
	 */
	char *path;
};

/**
 * Compare a decoded attribute value to a blank padded field
 */
static bool matches_field(private_pkcs11_uri_t *this, uri_attr_t attr,
						  unsigned char *field, size_t len)
{
	if (!this->set[attr])
	{	/* attributes not present in the URI match everything */
		return TRUE;
	}
	while (len && (field[len - 1] == ' ' || field[len - 1] == '\0'))
	{
		len--;
	}
	return chunk_equals(this->values[attr], chunk_create(field, len));
}

METHOD(pkcs11_uri_t, matches_library, bool,
	private_pkcs11_uri_t *this, CK_INFO *info)
{
	if (this->set[URI_LIBRARY_VERSION] &&
		(info->libraryVersion.major != this->version.major ||
		 info->libraryVersion.minor != this->version.minor))
	{
		return FALSE;
	}
	return matches_field(this, URI_LIBRARY_MANUFACTURER, info->manufacturerID,
						 sizeof(info->manufacturerID)) &&
		   matches_field(this, URI_LIBRARY_DESCRIPTION, info->libraryDescription,
						 sizeof(info->libraryDescription));
}

METHOD(pkcs11_uri_t, matches_slot, bool,
	private_pkcs11_uri_t *this, CK_SLOT_ID slot, CK_SLOT_INFO *info)
{
	if (this->set[URI_SLOT_ID] && slot != this->slot)
	{
		return FALSE;
	}
	return matches_field(this, URI_SLOT_MANUFACTURER, info->manufacturerID,
						 sizeof(info->manufacturerID)) &&
		   matches_field(this, URI_SLOT_DESCRIPTION, info->slotDescription,
						 sizeof(info->slotDescription));
}

METHOD(pkcs11_uri_t, matches_token, bool,
	private_pkcs11_uri_t *this, CK_TOKEN_INFO *info)
{
	return matches_field(this, URI_TOKEN, info->label,
						 sizeof(info->label)) &&
		   matches_field(this, URI_MANUFACTURER, info->manufacturerID,
						 sizeof(info->manufacturerID)) &&
		   matches_field(this, URI_MODEL, info->model,
						 sizeof(info->model)) &&
		   matches_field(this, URI_SERIAL, info->serialNumber,
						 sizeof(info->serialNumber));
}

METHOD(pkcs11_uri_t, get_class, bool,
	private_pkcs11_uri_t *this, CK_OBJECT_CLASS *class)
{
	if (this->set[URI_TYPE])
	{
		*class = this->class;
		return TRUE;
	}
	return FALSE;
}

METHOD(pkcs11_uri_t, fill_template, int,
	private_pkcs11_uri_t *this, CK_ATTRIBUTE_PTR tmpl)
{
	int count = 0;

	if (this->set[URI_TYPE])
	{
		tmpl[count++] = (CK_ATTRIBUTE){
			CKA_CLASS, &this->class, sizeof(this->class)
		};
	}
	if (this->set[URI_OBJECT])
	{
		tmpl[count++] = (CK_ATTRIBUTE){
			CKA_LABEL, this->values[URI_OBJECT].ptr,
			this->values[URI_OBJECT].len
		};
	}
	if (this->set[URI_ID])
	{
		tmpl[count++] = (CK_ATTRIBUTE){
			CKA_ID, this->values[URI_ID].ptr, this->values[URI_ID].len
		};
	}
	return count;
}

METHOD(pkcs11_uri_t, get_path, char*,
	private_pkcs11_uri_t *this)
{
	return this->path;
}

METHOD(pkcs11_uri_t, destroy, void,
	private_pkcs11_uri_t *this)
{
	int i;

	for (i = 0; i < URI_ATTR_MAX; i++)
	{
		chunk_clear(&this->values[i]);
	}
	free(this->path);
	free(this);
}

/**
 * Decode a hexadecimal digit
 */
static int hex_value(char c)
{
	if (c >= '0' && c <= '9')
	{
		return c - '0';
	}
	if (c >= 'a' && c <= 'f')
	{
		return c - 'a' + 10;
	}
	if (c >= 'A' && c <= 'F')
	{
		return c - 'A' + 10;
	}
	return -1;
}

/**
 * Percent-decode len bytes of str (RFC 3986, section 2.1), the result is
 * allocated with an additional null-terminator not included in its length
 */
static bool percent_decode(char *str, size_t len, chunk_t *value)
{
	u_char *pos;
	int hi, lo;

	*value = chunk_alloc(len + 1);
	pos = value->ptr;
	while (len)
	{
		if (*str == '%')
		{
			if (len < 3 ||
				(hi = hex_value(str[1])) < 0 || (lo = hex_value(str[2])) < 0)
			{
				chunk_free(value);
				return FALSE;
			}
			*pos++ = (hi << 4) | lo;
			str += 3;
			len -= 3;
			continue;
		}
		*pos++ = *str++;
		len--;
	}
	*pos = '\0';
	value->len = pos - value->ptr;
	return TRUE;
}

/**
 * Parse a decimal number of a decoded value
 */
static bool parse_number(char *str, u_long *number)
{
	char *end;

	if (!isdigit(*str))
	{
		return FALSE;
	}
	errno = 0;
	*number = strtoul(str, &end, 10);
	return !errno && end != str && *end == '\0';
}

/**
 * Parse the value of a path attribute that needs further processing
 */
static bool parse_value(private_pkcs11_uri_t *this, uri_attr_t attr)
{
	char *str = this->values[attr].ptr, *minor;
	u_long major = 0, number = 0;
	int i;

	switch (attr)
	{
		case URI_TYPE:
			for (i = 0; i < countof(types); i++)
			{
				if (streq(str, types[i].name))
				{
					this->class = types[i].class;
					return TRUE;
				}
			}
			return FALSE;
		case URI_LIBRARY_VERSION:
			/* "M" is interpreted as "M.0" */
			minor = strchr(str, '.');
			if (minor)
			{
				*minor++ = '\0';
				if (!parse_number(minor, &number))
				{
					return FALSE;
				}
			}
			if (!parse_number(str, &major) || major > 0xff || number > 0xff)
			{
				return FALSE;
			}
			this->version.major = major;
			this->version.minor = number;
			return TRUE;
		case URI_SLOT_ID:
			if (!parse_number(str, &number))
			{
				return FALSE;
			}
			this->slot = number;
			return TRUE;
		default:
			/* values may only contain null bytes for the binary id */
			return attr == URI_ID ||
				   strlen(str) == this->values[attr].len;
	}
}

/**
 * Parse a single path attribute
 */
static bool parse_attribute(private_pkcs11_uri_t *this, char *str, size_t len)
{
	char *eq;
	int i;

	eq = memchr(str, '=', len);
	if (!eq)
	{
		DBG1(DBG_CFG, "invalid PKCS#11 URI path attribute '%.*s'", (int)len,
			 str);
		return FALSE;
	}
	for (i = 0; i < URI_ATTR_MAX; i++)
	{
		if (strlen(attr_names[i]) == eq - str &&
			strneq(attr_names[i], str, eq - str))
		{
			break;
		}
	}
	if (i == URI_ATTR_MAX)
	{	/* an unrecognized path attribute must not match anything */
		DBG1(DBG_CFG, "unsupported PKCS#11 URI path attribute '%.*s'",
			 (int)(eq - str), str);
		return FALSE;
	}
	if (this->set[i])
	{
		DBG1(DBG_CFG, "duplicate PKCS#11 URI path attribute '%s'",
			 attr_names[i]);
		return FALSE;
	}
	eq++;
	if (!percent_decode(eq, len - (eq - str), &this->values[i]) ||
		!parse_value(this, i))
	{
		DBG1(DBG_CFG, "invalid value for PKCS#11 URI path attribute '%s'",
			 attr_names[i]);
		return FALSE;
	}
	this->set[i] = TRUE;
	return TRUE;
}

/*
 * Described in header
 */
pkcs11_uri_t *pkcs11_uri_create(char *uri)
{
	private_pkcs11_uri_t *this;
	char *pos, *end, *sep;

	if (!uri || !strcasepfx(uri, "pkcs11:"))
	{
		return NULL;
	}

	INIT(this,
		.public = {
			.matches_library = _matches_library,
			.matches_slot = _matches_slot,
			.matches_token = _matches_token,
			.get_class = _get_class,
			.fill_template = _fill_template,
			.get_path = _get_path,
			.destroy = _destroy,
		},
	);

	/* query attributes (pin-value, module-name etc.) are ignored, the query
	 * might contain a PIN, so it's never stored or logged */
	this->path = strndup(uri, strcspn(uri, "?"));

	pos = this->path + strlen("pkcs11:");
	end = pos + strlen(pos);
	while (pos < end)
	{
		sep = memchr(pos, ';', end - pos) ?: end;
		if (sep > pos && !parse_attribute(this, pos, sep - pos))
		{
			destroy(this);
			return NULL;
		}
		pos = sep + 1;
	}
	return &this->public;
}
