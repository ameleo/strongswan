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

#include <test_suite.h>

#include <pkcs11_uri.h>

/**
 * Copy a string to a blank padded field
 */
static void pad(unsigned char *field, size_t len, char *str)
{
	memset(field, ' ', len);
	memcpy(field, str, strlen(str));
}

/**
 * Create token info with the given label, manufacturer, model and serial
 */
static CK_TOKEN_INFO token_info(char *label, char *manufacturer, char *model,
								char *serial)
{
	CK_TOKEN_INFO info = {};

	pad(info.label, sizeof(info.label), label);
	pad(info.manufacturerID, sizeof(info.manufacturerID), manufacturer);
	pad(info.model, sizeof(info.model), model);
	pad(info.serialNumber, sizeof(info.serialNumber), serial);
	return info;
}

static struct {
	char *uri;
	char *path;
	bool match;
} token_data[] = {
	{ "pkcs11:", "pkcs11:", TRUE },
	{ "pkcs11:token=certmonger", "pkcs11:token=certmonger", TRUE },
	{ "PKCS11:token=certmonger", "PKCS11:token=certmonger", TRUE },
	{ "pkcs11:token=cert%6Donger", "pkcs11:token=cert%6Donger", TRUE },
	{ "pkcs11:token=certmonger;manufacturer=tpm2-software.github.io;"
	  "model=SW%20%20%20TPM;serial=0000000000000000",
	  "pkcs11:token=certmonger;manufacturer=tpm2-software.github.io;"
	  "model=SW%20%20%20TPM;serial=0000000000000000", TRUE },
	{ "pkcs11:token=certmonger;object=vpn?pin-value=1234",
	  "pkcs11:token=certmonger;object=vpn", TRUE },
	{ "pkcs11:token=certmonger?module-name=tpm2_pkcs11&pin-source=file:/x",
	  "pkcs11:token=certmonger", TRUE },
	{ "pkcs11:token=certmonger;", "pkcs11:token=certmonger;", TRUE },
	{ "pkcs11:token=certmonge", "pkcs11:token=certmonge", FALSE },
	{ "pkcs11:token=certmonger2", "pkcs11:token=certmonger2", FALSE },
	{ "pkcs11:token=Certmonger", "pkcs11:token=Certmonger", FALSE },
	{ "pkcs11:token=certmonger;serial=1", "pkcs11:token=certmonger;serial=1",
	  FALSE },
	{ "pkcs11:model=SW", "pkcs11:model=SW", FALSE },
};

START_TEST(test_token)
{
	CK_TOKEN_INFO info;
	pkcs11_uri_t *uri;

	info = token_info("certmonger", "tpm2-software.github.io", "SW   TPM",
					  "0000000000000000");
	uri = pkcs11_uri_create(token_data[_i].uri);
	ck_assert(uri);
	ck_assert_str_eq(uri->get_path(uri), token_data[_i].path);
	ck_assert(uri->matches_token(uri, &info) == token_data[_i].match);
	uri->destroy(uri);
}
END_TEST

START_TEST(test_token_full_label)
{
	CK_TOKEN_INFO info;
	pkcs11_uri_t *uri;

	/* a label using all 32 characters, without padding or terminator */
	info = token_info("0123456789abcdef0123456789abcdef", "m", "m", "s");
	uri = pkcs11_uri_create("pkcs11:token=0123456789abcdef0123456789abcdef");
	ck_assert(uri);
	ck_assert(uri->matches_token(uri, &info));
	uri->destroy(uri);

	uri = pkcs11_uri_create("pkcs11:token=0123456789abcdef0123456789abcde");
	ck_assert(uri);
	ck_assert(!uri->matches_token(uri, &info));
	uri->destroy(uri);
}
END_TEST

START_TEST(test_template)
{
	CK_ATTRIBUTE tmpl[3];
	CK_OBJECT_CLASS class;
	pkcs11_uri_t *uri;

	uri = pkcs11_uri_create("pkcs11:token=certmonger;object=sezaleo-tpm;"
							"type=cert");
	ck_assert(uri);
	ck_assert(uri->get_class(uri, &class));
	ck_assert_int_eq(class, CKO_CERTIFICATE);
	ck_assert_int_eq(uri->fill_template(uri, tmpl), 2);
	ck_assert_int_eq(tmpl[0].type, CKA_CLASS);
	ck_assert_int_eq(*(CK_OBJECT_CLASS*)tmpl[0].pValue, CKO_CERTIFICATE);
	ck_assert_int_eq(tmpl[1].type, CKA_LABEL);
	ck_assert_chunk_eq(chunk_create(tmpl[1].pValue, tmpl[1].ulValueLen),
					   chunk_from_str("sezaleo-tpm"));
	uri->destroy(uri);

	uri = pkcs11_uri_create("pkcs11:id=%01%Ab%00%ff;object=my%20key;"
							"type=private");
	ck_assert(uri);
	ck_assert(uri->get_class(uri, &class));
	ck_assert_int_eq(class, CKO_PRIVATE_KEY);
	ck_assert_int_eq(uri->fill_template(uri, tmpl), 3);
	ck_assert_int_eq(tmpl[1].type, CKA_LABEL);
	ck_assert_chunk_eq(chunk_create(tmpl[1].pValue, tmpl[1].ulValueLen),
					   chunk_from_str("my key"));
	ck_assert_int_eq(tmpl[2].type, CKA_ID);
	ck_assert_chunk_eq(chunk_create(tmpl[2].pValue, tmpl[2].ulValueLen),
					   chunk_from_chars(0x01, 0xab, 0x00, 0xff));
	uri->destroy(uri);

	uri = pkcs11_uri_create("pkcs11:token=certmonger;object=");
	ck_assert(uri);
	ck_assert(!uri->get_class(uri, &class));
	ck_assert_int_eq(uri->fill_template(uri, tmpl), 1);
	ck_assert_int_eq(tmpl[0].type, CKA_LABEL);
	ck_assert_int_eq(tmpl[0].ulValueLen, 0);
	uri->destroy(uri);
}
END_TEST

START_TEST(test_library_slot)
{
	CK_INFO info = {
		.libraryVersion = { 1, 9 },
	};
	CK_SLOT_INFO slot = {};
	pkcs11_uri_t *uri;

	pad(info.manufacturerID, sizeof(info.manufacturerID), "tpm2-software");
	pad(info.libraryDescription, sizeof(info.libraryDescription), "TPM2.0");
	pad(slot.manufacturerID, sizeof(slot.manufacturerID), "Intel");
	pad(slot.slotDescription, sizeof(slot.slotDescription), "slot a");

	uri = pkcs11_uri_create("pkcs11:library-manufacturer=tpm2-software;"
							"library-description=TPM2.0;library-version=1.9;"
							"slot-manufacturer=Intel;slot-description=slot%20a;"
							"slot-id=3");
	ck_assert(uri);
	ck_assert(uri->matches_library(uri, &info));
	ck_assert(uri->matches_slot(uri, 3, &slot));
	ck_assert(!uri->matches_slot(uri, 2, &slot));
	uri->destroy(uri);

	uri = pkcs11_uri_create("pkcs11:library-version=1");
	ck_assert(uri);
	ck_assert(!uri->matches_library(uri, &info));
	info.libraryVersion.minor = 0;
	ck_assert(uri->matches_library(uri, &info));
	ck_assert(uri->matches_slot(uri, 7, &slot));
	uri->destroy(uri);
}
END_TEST

static char *invalid_data[] = {
	NULL,
	"",
	"pkcs11",
	"file:///etc/cert.pem",
	"/etc/cert.pem",
	"pkcs11:object",
	"pkcs11:foo=bar",
	"pkcs11:x-vendor=bar",
	"pkcs11:Object=bar",
	"pkcs11:object=a;object=b",
	"pkcs11:id=%zz",
	"pkcs11:id=%1",
	"pkcs11:id=%",
	"pkcs11:object=a%00b",
	"pkcs11:type=certificate",
	"pkcs11:library-version=a",
	"pkcs11:library-version=1.",
	"pkcs11:library-version=1.2.3",
	"pkcs11:library-version=256",
	"pkcs11:library-version=-1",
	"pkcs11:slot-id=",
	"pkcs11:slot-id=1x",
	"pkcs11:slot-id=+1",
};

START_TEST(test_invalid)
{
	pkcs11_uri_t *uri;

	uri = pkcs11_uri_create(invalid_data[_i]);
	ck_assert(!uri);
}
END_TEST

Suite *pkcs11_uri_suite_create()
{
	Suite *s;
	TCase *tc;

	s = suite_create("pkcs11 uri");

	tc = tcase_create("token");
	tcase_add_loop_test(tc, test_token, 0, countof(token_data));
	tcase_add_test(tc, test_token_full_label);
	suite_add_tcase(s, tc);

	tc = tcase_create("template");
	tcase_add_test(tc, test_template);
	suite_add_tcase(s, tc);

	tc = tcase_create("library/slot");
	tcase_add_test(tc, test_library_slot);
	suite_add_tcase(s, tc);

	tc = tcase_create("invalid");
	tcase_add_loop_test(tc, test_invalid, 0, countof(invalid_data));
	suite_add_tcase(s, tc);

	return s;
}
