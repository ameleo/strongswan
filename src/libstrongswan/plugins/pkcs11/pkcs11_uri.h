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

/**
 * @defgroup pkcs11_uri pkcs11_uri
 * @{ @ingroup pkcs11
 */

#ifndef PKCS11_URI_H_
#define PKCS11_URI_H_

typedef struct pkcs11_uri_t pkcs11_uri_t;

#include "pkcs11.h"

#include <library.h>

/**
 * Parsed PKCS#11 URI as defined in RFC 7512.
 *
 * All path attributes defined by RFC 7512 are supported, a URI containing
 * any other path attribute is rejected, as it would not match any object
 * (section 2.5).  Query attributes are ignored, as only modules configured
 * for the plugin are used and PINs are provided by other means.
 */
struct pkcs11_uri_t {

	/**
	 * Check if the library attributes of the URI match the given library.
	 *
	 * @param info		library info as returned by C_GetInfo()
	 * @return			TRUE if the library matches
	 */
	bool (*matches_library)(pkcs11_uri_t *this, CK_INFO *info);

	/**
	 * Check if the slot attributes of the URI match the given slot.
	 *
	 * @param slot		slot ID
	 * @param info		slot info as returned by C_GetSlotInfo()
	 * @return			TRUE if the slot matches
	 */
	bool (*matches_slot)(pkcs11_uri_t *this, CK_SLOT_ID slot,
						 CK_SLOT_INFO *info);

	/**
	 * Check if the token attributes of the URI match the given token.
	 *
	 * @param info		token info as returned by C_GetTokenInfo()
	 * @return			TRUE if the token matches
	 */
	bool (*matches_token)(pkcs11_uri_t *this, CK_TOKEN_INFO *info);

	/**
	 * Get the object class from the "type" attribute, if any.
	 *
	 * @param class		receives the object class
	 * @return			TRUE if the URI contains a "type" attribute
	 */
	bool (*get_class)(pkcs11_uri_t *this, CK_OBJECT_CLASS *class);

	/**
	 * Add the object attributes of the URI (CKA_CLASS, CKA_LABEL, CKA_ID) to
	 * a search template.  The values point to internal data.
	 *
	 * @param tmpl		template to fill, must provide room for 3 attributes
	 * @return			number of attributes added
	 */
	int (*fill_template)(pkcs11_uri_t *this, CK_ATTRIBUTE_PTR tmpl);

	/**
	 * Get the URI without query component, safe for logging.
	 *
	 * @return			URI without query component (internal data)
	 */
	char* (*get_path)(pkcs11_uri_t *this);

	/**
	 * Destroy a pkcs11_uri_t.
	 */
	void (*destroy)(pkcs11_uri_t *this);
};

/**
 * Parse a PKCS#11 URI.
 *
 * @param uri			URI string, starting with "pkcs11:"
 * @return				parsed URI, NULL if invalid or not supported
 */
pkcs11_uri_t *pkcs11_uri_create(char *uri);

#endif /** PKCS11_URI_H_ @}*/
