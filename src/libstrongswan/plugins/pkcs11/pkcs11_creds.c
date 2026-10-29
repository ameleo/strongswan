/*
 * Copyright (C) 2010 Martin Willi
 *
 * Copyright (C) secunet Security Networks AG
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

#include "pkcs11_creds.h"
#include "pkcs11_manager.h"
#include "pkcs11_uri.h"

#include <utils/debug.h>
#include <collections/linked_list.h>

typedef struct private_pkcs11_creds_t private_pkcs11_creds_t;

/**
 * Private data of an pkcs11_creds_t object.
 */
struct private_pkcs11_creds_t {

	/**
	 * Public pkcs11_creds_t interface.
	 */
	pkcs11_creds_t public;

	/**
	 * PKCS# library
	 */
	pkcs11_library_t *lib;

	/**
	 * Token slot
	 */
	CK_SLOT_ID slot;

	/**
	 * List of trusted certificates
	 */
	linked_list_t *trusted;

	/**
	 * List of untrusted certificates
	 */
	linked_list_t *untrusted;
};

/**
 * Find certificates, optionally trusted
 */
static void find_certificates(private_pkcs11_creds_t *this,
							  CK_SESSION_HANDLE session)
{
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	CK_BBOOL trusted = TRUE;
	CK_ATTRIBUTE tmpl[] = {
		{CKA_CLASS, &class, sizeof(class)},
		{CKA_CERTIFICATE_TYPE, &type, sizeof(type)},
	};
	CK_OBJECT_HANDLE object;
	CK_ATTRIBUTE attr[] = {
		{CKA_VALUE, NULL, 0},
		{CKA_LABEL, NULL, 0},
		{CKA_TRUSTED, &trusted, sizeof(trusted)}
	};
	enumerator_t *enumerator;
	linked_list_t *raw;
	certificate_t *cert;
	struct {
		chunk_t value;
		chunk_t label;
		bool trusted;
	} *entry;
	int count = countof(attr);

	/* store result in a temporary list, avoid recursive operation */
	raw = linked_list_create();
	enumerator = this->lib->create_object_enumerator(this->lib,
									session, tmpl, countof(tmpl), attr, count);
	while (enumerator->enumerate(enumerator, &object))
	{
		if (attr[0].ulValueLen == CK_UNAVAILABLE_INFORMATION ||
			attr[1].ulValueLen == CK_UNAVAILABLE_INFORMATION)
		{
			continue;
		}
		INIT(entry,
			.value = chunk_clone(chunk_create(attr[0].pValue, attr[0].ulValueLen)),
			.label = chunk_clone(chunk_create(attr[1].pValue, attr[1].ulValueLen)),
			/* assume trusted certificates if attribute is not available */
			.trusted = attr[2].ulValueLen == CK_UNAVAILABLE_INFORMATION || trusted,
		);
		raw->insert_last(raw, entry);
	}
	enumerator->destroy(enumerator);

	while (raw->remove_first(raw, (void**)&entry) == SUCCESS)
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							BUILD_BLOB_ASN1_DER, entry->value,
							BUILD_END);
		if (cert)
		{
			DBG1(DBG_CFG, "    loaded %strusted cert '%.*s'",
				 entry->trusted ? "" : "un", (int)entry->label.len,
				 entry->label.ptr);
			/* trusted certificates are also returned as untrusted */
			this->untrusted->insert_last(this->untrusted, cert);
			if (entry->trusted)
			{
				this->trusted->insert_last(this->trusted, cert->get_ref(cert));
			}
		}
		else
		{
			DBG1(DBG_CFG, "    loading cert '%.*s' failed",
				(int)entry->label.len, entry->label.ptr);
		}
		free(entry->value.ptr);
		free(entry->label.ptr);
		free(entry);
	}
	raw->destroy(raw);
}

/**
 * Load in the certificates from the token
 */
static bool load_certificates(private_pkcs11_creds_t *this)
{
	CK_SESSION_HANDLE session;
	CK_RV rv;

	rv = this->lib->f->C_OpenSession(this->slot, CKF_SERIAL_SESSION,
									 NULL, NULL, &session);
	if (rv != CKR_OK)
	{
		DBG1(DBG_CFG, "opening session failed: %N", ck_rv_names, rv);
		return FALSE;
	}

	find_certificates(this, session);

	this->lib->f->C_CloseSession(session);
	return TRUE;
}

CALLBACK(certs_filter, bool,
	identification_t *id, enumerator_t *orig, va_list args)
{
	public_key_t *public;
	certificate_t *cert, **out;

	VA_ARGS_VGET(args, out);

	while (orig->enumerate(orig, &cert))
	{
		if (id == NULL || cert->has_subject(cert, id))
		{
			*out = cert;
			return TRUE;
		}
		public = cert->get_public_key(cert);
		if (public)
		{
			if (public->has_fingerprint(public, id->get_encoding(id)))
			{
				public->destroy(public);
				*out = cert;
				return TRUE;
			}
			public->destroy(public);
		}
	}
	return FALSE;
}

METHOD(credential_set_t, create_cert_enumerator, enumerator_t*,
	private_pkcs11_creds_t *this, certificate_type_t cert, key_type_t key,
	identification_t *id, bool trusted)
{
	enumerator_t *inner;

	if (cert != CERT_X509 && cert != CERT_ANY)
	{
		return NULL;
	}
	if (trusted)
	{
		inner = this->trusted->create_enumerator(this->trusted);
	}
	else
	{
		inner = this->untrusted->create_enumerator(this->untrusted);
	}
	return enumerator_create_filter(inner, certs_filter, id, NULL);
}

METHOD(pkcs11_creds_t, get_library, pkcs11_library_t*,
	private_pkcs11_creds_t *this)
{
	return this->lib;
}

METHOD(pkcs11_creds_t, get_slot, CK_SLOT_ID,
	private_pkcs11_creds_t *this)
{
	return this->slot;
}

METHOD(pkcs11_creds_t, destroy, void,
	private_pkcs11_creds_t *this)
{
	this->trusted->destroy_offset(this->trusted,
								offsetof(certificate_t, destroy));
	this->untrusted->destroy_offset(this->untrusted,
								offsetof(certificate_t, destroy));
	free(this);
}

/**
 * See header
 */
pkcs11_creds_t *pkcs11_creds_create(pkcs11_library_t *p11, CK_SLOT_ID slot)
{
	private_pkcs11_creds_t *this;

	INIT(this,
		.public = {
			.set = {
				.create_shared_enumerator = (void*)enumerator_create_empty,
				.create_private_enumerator = (void*)enumerator_create_empty,
				.create_cert_enumerator = _create_cert_enumerator,
				.create_cdp_enumerator  = (void*)enumerator_create_empty,
				.cache_cert = (void*)nop,
			},
			.get_library = _get_library,
			.get_slot = _get_slot,
			.destroy = _destroy,
		},
		.lib = p11,
		.slot = slot,
		.trusted = linked_list_create(),
		.untrusted = linked_list_create(),
	);

	if (!load_certificates(this))
	{
		destroy(this);
		return NULL;
	}

	return &this->public;
}

/**
 * Check if the library, slot and token match the given URI
 */
static bool matches_uri(pkcs11_uri_t *uri, pkcs11_library_t *p11,
						CK_SLOT_ID slot)
{
	CK_INFO info;
	CK_SLOT_INFO slot_info;
	CK_TOKEN_INFO token_info;

	return p11->f->C_GetInfo(&info) == CKR_OK &&
		   uri->matches_library(uri, &info) &&
		   p11->f->C_GetSlotInfo(slot, &slot_info) == CKR_OK &&
		   uri->matches_slot(uri, slot, &slot_info) &&
		   p11->f->C_GetTokenInfo(slot, &token_info) == CKR_OK &&
		   uri->matches_token(uri, &token_info);
}

/**
 * See header.
 */
bool pkcs11_creds_find_by_uri(char *str, pkcs11_library_t **p11_out,
							  CK_SLOT_ID *slot_out, chunk_t *ckaid,
							  chunk_t *value)
{
	CK_OBJECT_CLASS class = CKO_CERTIFICATE;
	CK_CERTIFICATE_TYPE type = CKC_X_509;
	CK_ATTRIBUTE tmpl[5] = {
		{CKA_CERTIFICATE_TYPE, &type, sizeof(type)},
	};
	CK_ATTRIBUTE attr[] = {
		{CKA_VALUE, NULL, 0},
		{CKA_ID, NULL, 0},
	};
	CK_OBJECT_HANDLE object;
	CK_SESSION_HANDLE session;
	CK_SLOT_ID current;
	CK_RV rv;
	pkcs11_manager_t *manager;
	pkcs11_library_t *p11;
	pkcs11_uri_t *uri;
	enumerator_t *enumerator, *certs;
	int count = 1, found = 0;

	*ckaid = chunk_empty;
	if (value)
	{
		*value = chunk_empty;
	}
	uri = pkcs11_uri_create(str);
	if (!uri)
	{	/* don't log the URI, it might contain a PIN */
		DBG1(DBG_CFG, "invalid PKCS#11 URI");
		return FALSE;
	}
	if (uri->get_class(uri, &class) && class != CKO_CERTIFICATE)
	{
		DBG1(DBG_CFG, "PKCS#11 URI '%s' does not refer to a certificate",
			 uri->get_path(uri));
		uri->destroy(uri);
		return FALSE;
	}
	count += uri->fill_template(uri, &tmpl[count]);
	if (!uri->get_class(uri, &class))
	{
		tmpl[count++] = (CK_ATTRIBUTE){CKA_CLASS, &class, sizeof(class)};
	}

	manager = lib->get(lib, "pkcs11-manager");
	if (!manager)
	{
		uri->destroy(uri);
		return FALSE;
	}
	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &current))
	{
		if (!matches_uri(uri, p11, current))
		{
			continue;
		}
		rv = p11->f->C_OpenSession(current, CKF_SERIAL_SESSION, NULL, NULL,
								   &session);
		if (rv != CKR_OK)
		{
			DBG1(DBG_CFG, "opening PKCS#11 session failed: %N", ck_rv_names, rv);
			continue;
		}
		certs = p11->create_object_enumerator(p11, session, tmpl, count,
											  attr, countof(attr));
		while (certs->enumerate(certs, &object))
		{
			if (found++ || attr[0].ulValueLen == CK_UNAVAILABLE_INFORMATION)
			{
				continue;
			}
			*p11_out = p11;
			*slot_out = current;
			if (attr[1].ulValueLen != CK_UNAVAILABLE_INFORMATION)
			{
				*ckaid = chunk_clone(chunk_create(attr[1].pValue,
												  attr[1].ulValueLen));
			}
			if (value)
			{
				*value = chunk_clone(chunk_create(attr[0].pValue,
												  attr[0].ulValueLen));
			}
			DBG1(DBG_CFG, "found certificate '%s' on PKCS#11 token '%s':%d",
				 uri->get_path(uri), p11->get_name(p11), current);
		}
		certs->destroy(certs);
		p11->f->C_CloseSession(session);
	}
	enumerator->destroy(enumerator);

	if (found != 1 || (value && !value->ptr))
	{
		if (found > 1)
		{
			DBG1(DBG_CFG, "PKCS#11 URI '%s' matches %d certificates, it must "
				 "identify a single one", uri->get_path(uri), found);
		}
		else if (!found)
		{
			DBG1(DBG_CFG, "no PKCS#11 certificate found matching '%s'",
				 uri->get_path(uri));
		}
		else
		{
			DBG1(DBG_CFG, "reading PKCS#11 certificate '%s' failed",
				 uri->get_path(uri));
		}
		chunk_free(ckaid);
		if (value)
		{
			chunk_free(value);
		}
		uri->destroy(uri);
		return FALSE;
	}
	uri->destroy(uri);
	return TRUE;
}

/**
 * Load the certificate referenced by a PKCS#11 URI
 */
static certificate_t *load_by_uri(char *uri)
{
	pkcs11_library_t *p11;
	certificate_t *cert;
	CK_SLOT_ID slot;
	chunk_t ckaid, data;

	if (!pkcs11_creds_find_by_uri(uri, &p11, &slot, &ckaid, &data))
	{
		return NULL;
	}
	cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
							  BUILD_BLOB_ASN1_DER, data, BUILD_END);
	if (!cert)
	{
		DBG1(DBG_CFG, "parsing PKCS#11 certificate on '%s':%d failed",
			 p11->get_name(p11), slot);
	}
	chunk_free(&ckaid);
	chunk_free(&data);
	return cert;
}

/**
 * See header.
 */
certificate_t *pkcs11_creds_load(certificate_type_t type, va_list args)
{
	chunk_t keyid = chunk_empty, data = chunk_empty;
	enumerator_t *enumerator, *certs;
	pkcs11_manager_t *manager;
	pkcs11_library_t *p11;
	certificate_t *cert = NULL;
	CK_SLOT_ID current, slot = -1;
	char *module = NULL, *uri = NULL;

	while (TRUE)
	{
		switch (va_arg(args, builder_part_t))
		{
			case BUILD_PKCS11_KEYID:
				keyid = va_arg(args, chunk_t);
				continue;
			case BUILD_PKCS11_SLOT:
				slot = va_arg(args, int);
				continue;
			case BUILD_PKCS11_MODULE:
				module = va_arg(args, char*);
				continue;
			case BUILD_PKCS11_URI:
				uri = va_arg(args, char*);
				continue;
			case BUILD_END:
				break;
			default:
				return NULL;
		}
		break;
	}
	if (uri)
	{
		return load_by_uri(uri);
	}
	if (!keyid.len)
	{
		return NULL;
	}

	manager = lib->get(lib, "pkcs11-manager");
	if (!manager)
	{
		return NULL;
	}
	enumerator = manager->create_token_enumerator(manager);
	while (enumerator->enumerate(enumerator, &p11, &current))
	{
		CK_OBJECT_CLASS class = CKO_CERTIFICATE;
		CK_CERTIFICATE_TYPE ck_type = CKC_X_509;
		CK_ATTRIBUTE tmpl[] = {
			{CKA_CLASS, &class, sizeof(class)},
			{CKA_CERTIFICATE_TYPE, &ck_type, sizeof(ck_type)},
			{CKA_ID, keyid.ptr, keyid.len},
		};
		CK_ATTRIBUTE attr[] = {
			{CKA_VALUE, NULL, 0},
		};
		CK_OBJECT_HANDLE object;
		CK_SESSION_HANDLE session;
		CK_RV rv;

		if (slot != -1 && slot != current)
		{
			continue;
		}
		if (module && !streq(module, p11->get_name(p11)))
		{
			continue;
		}

		rv = p11->f->C_OpenSession(current, CKF_SERIAL_SESSION, NULL, NULL,
								   &session);
		if (rv != CKR_OK)
		{
			DBG1(DBG_CFG, "opening PKCS#11 session failed: %N", ck_rv_names, rv);
			continue;
		}
		certs = p11->create_object_enumerator(p11, session,
									tmpl, countof(tmpl), attr, countof(attr));
		if (certs->enumerate(certs, &object) &&
			attr[0].ulValueLen != CK_UNAVAILABLE_INFORMATION)
		{
			data = chunk_clone(chunk_create(attr[0].pValue, attr[0].ulValueLen));
		}
		certs->destroy(certs);
		p11->f->C_CloseSession(session);

		if (data.ptr)
		{
			break;
		}
	}
	enumerator->destroy(enumerator);

	if (data.ptr)
	{
		cert = lib->creds->create(lib->creds, CRED_CERTIFICATE, CERT_X509,
								  BUILD_BLOB_ASN1_DER, data, BUILD_END);
		free(data.ptr);
		if (!cert)
		{
			DBG1(DBG_CFG, "parsing PKCS#11 certificate %#B failed", &keyid);
		}
	}
	else
	{
		DBG1(DBG_CFG, "PKCS#11 certificate %#B not found", &keyid);
	}
	return cert;
}
