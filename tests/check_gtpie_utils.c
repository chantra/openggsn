#include <stdlib.h>
#include <stdio.h>

#include "../gtpdump/gtpie_utils.h"
#include "check_gtpie_utils.h"

/**
 * APN DECODE
 */
START_TEST (test_gtpie_utils_apn_decode)
{
	char *apn_decoded = NULL;
	char *apn_result = "test.apn.name";
	struct ul255_t apnie = { 14, { 0x04, 't', 'e', 's', 't', 0x03, 'a', 'p', 'n', 0x04, 'n', 'a', 'm', 'e'} };

	apn_decoded = gtpie_utils_apn_decode (apnie);
	fail_unless (strcmp (apn_decoded, apn_result) == 0, "APN decoded as %s instead of %s!", apn_decoded, apn_result);
}
END_TEST


START_TEST (test_gtpie_utils_apn_decode_segfault)
{
	char *apn_decoded = NULL;
	char *apn_result = "test.apn.name";
	struct ul255_t apnie = { BUFSIZ+1, { 0x04, 't', 'e', 's', 't', 0x03, 'a', 'p', 'n', 0x04, 'n', 'a', 'm', 'e'} };

	apn_decoded = gtpie_utils_apn_decode (apnie);
	fail_unless (strcmp (apn_decoded, "") == 0, "APN overflow not properly handled!");
}
END_TEST

/**
 * MSISDN Decode/Encode
 */

START_TEST (test_gtpie_utils_msisdn_decode)
{
  struct ul16_t msisdn = { 7, {0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0xF1} };
  char *result = "+12345678901";
  char *msisdn_decoded = NULL;

  msisdn_decoded = gtpie_utils_msisdn_decode (msisdn.v, msisdn.l);
  fail_unless (strcmp (result, msisdn_decoded) == 0, "MSISDN decoded as %s instead of %s!", msisdn_decoded, result);
}
END_TEST

START_TEST (test_gtpie_utils_msisdn_encode)
{
	char *msisdn = "+12345678901";
  struct ul16_t result = { 7, {0x91, 0x21, 0x43, 0x65, 0x87, 0x09, 0xF1} };
  struct ul16_t msisdn_encoded;
	int rc;

	rc = gtpie_utils_msisdn_encode (msisdn, &msisdn_encoded.v, &msisdn_encoded.l, sizeof (msisdn_encoded.v));
	fail_unless ( result.l == msisdn_encoded.l, "MSISDN encoded with length %d instead of %d!", result.l, msisdn_encoded.l);
  fail_unless (strncmp (result.v, msisdn_encoded.v, result.l) == 0, "MSISDN encoded differ from expected result!");
}
END_TEST


/**
 * IMSI Decode/Encode
 */
START_TEST (test_gtpie_utils_imsi_decode)
{
	uint64_t imsi;
	char imsi_bytearray[] = {0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5};
	char *result = "123456789012345";
	char *imsi_decoded = NULL;

	imsi = *((uint64_t *)imsi_bytearray);
	imsi_decoded = gtpie_utils_imsi_decode (imsi);
	fail_unless (strcmp (result, imsi_decoded) == 0, "IMSI decoded as %s instead of %s!", imsi_decoded, result);
}
END_TEST

START_TEST (test_gtpie_utils_imsi_encode)
{
	char imsi_bytearray[] = {0x21, 0x43, 0x65, 0x87, 0x09, 0x21, 0x43, 0xF5};
	char *imsi = "123456789012345";
	uint64_t result;
	int rc;

	rc = gtpie_utils_imsi_encode (imsi, &result);
	fail_unless (rc == 0, "gtpie_utils_imsi_encode return non 0");
	fail_unless (memcmp (&result, imsi_bytearray, sizeof( result )) == 0, "IMSI encoded differ from expected result!");
}
END_TEST


/**
 * TBCD Decode/Encode
 */
START_TEST (test_gtpie_utils_tbcd_decode)
{
	struct ul16_t tbcd = { 6, {0x21, 0x43, 0x65, 0x87, 0x09, 0xF1} };
	char *result = "12345678901";
	char *tbcd_decoded = NULL;

	tbcd_decoded = gtpie_utils_tbcd_decode (tbcd.v, tbcd.l);
	fail_unless (strcmp (result, tbcd_decoded) == 0, "TBCD decoded as %s instead of %s!", tbcd_decoded, result);
}
END_TEST

START_TEST (test_gtpie_utils_tbcd_decode_segfault)
{
	struct ul16_t tbcd = { BUFSIZ+1, {0x21, 0x43, 0x65, 0x87, 0x09, 0xF1} };
	char *result = "12345678901";
	char *tbcd_decoded = NULL;

	tbcd_decoded = gtpie_utils_tbcd_decode (tbcd.v, tbcd.l);
}
END_TEST

START_TEST (test_gtpie_utils_tbcd_encode)
{
	char *decoded = "12345678901";
	char *decoded2 = "123456789012";
	char *decoded3 = "1234567890123456789012345678901234";
	char *decoded4 = "12345678901234567890123456789012";
	struct ul16_t result;
	struct ul16_t tbcd = { 6, {0x21, 0x43, 0x65, 0x87, 0x09, 0xF1} };
	int rc;

	/* normal test with filling */
	rc = gtpie_utils_tbcd_encode (decoded, &result.v, &result.l, sizeof (result.v));
	fail_unless (rc == 0, "gtpie_utils_tbcd_decode exit with RC: %d!", rc);
	fail_unless (result.l == tbcd.l, "TBCD encoded as length %d when %d is expected!", result.l, tbcd.l);
	fail_unless (memcmp (result.v, tbcd.v, result.l) == 0, "TBCD encoded differ from expected result!");

	/* normal test with no filling */
	strncpy(tbcd.v, "\x21\x43\x65\x87\x09\x21", 6 );
	rc = gtpie_utils_tbcd_encode (decoded2, &result.v, &result.l, sizeof (result.v));
	fail_unless (result.l == tbcd.l, "TBCD (2) encoded as length %d when %d is expected!", result.l, tbcd.l);
	fail_unless (memcmp (result.v, tbcd.v, result.l) == 0, "TBCD (2) encoded differ from expected result!");

	/** encoding value longer than size of buffer
	 * function should not return 0
	 */
	tbcd.l = 16;
	strncpy(tbcd.v, "\x21\x43\x65\x87\x09\x21\x43\x65\x87\x09\x21\x43\x65\x87\x09\x21", 16 );
	rc = gtpie_utils_tbcd_encode (decoded3, &result.v, &result.l, sizeof (result.v));
	fail_unless (result.l == tbcd.l, "TBCD (3) encoded as length %d when %d is expected!", result.l, tbcd.l);
	fail_unless (memcmp (result.v, tbcd.v, result.l) == 0, "TBCD (3) encoded differ from expected result!");
	fail_unless (rc != 0, "TBCD (3) string to encode was too long, rc should not have returned 0!");

	/** encoding value is exactly the size of the buffer
	 * function should return 0
	 */
	rc = gtpie_utils_tbcd_encode (decoded4, &result.v, &result.l, sizeof (result.v));
	fail_unless (result.l == tbcd.l, "TBCD (4) encoded as length %d when %d is expected!", result.l, tbcd.l);
	fail_unless (memcmp (result.v, tbcd.v, result.l) == 0, "TBCD (4) encoded differ from expected result!");
	fail_unless (rc == 0, "TBCD (4) rc should have returned 0!");

}
END_TEST

START_TEST (test_gtpie_utils_tbcd_encode_0size)
{
	char *decoded = "";
	struct ul16_t result;
	struct ul16_t tbcd = { 0, {} };
	int rc;

	rc = gtpie_utils_tbcd_encode (decoded, &result.v, &result.l, sizeof (result.v));
	fail_unless (rc == 0, "gtpie_utils_tbcd_decode exit with RC: %d!", rc);
	fail_unless (result.l == tbcd.l, "TBCD encoded as length %d when %d is expected!", result.l, tbcd.l);
	fail_unless (memcmp (result.v, tbcd.v, result.l) == 0, "TBCD encoded differ from expected result!");
}
END_TEST


Suite *
gtpie_utils_suite (void){
	Suite *s = suite_create ("GTPIE_UTILS");

	/* Core test case */
	TCase *tc_core = tcase_create ("Core");
	/* APN */
	tcase_add_test (tc_core, test_gtpie_utils_apn_decode);
	tcase_add_exit_test (tc_core, test_gtpie_utils_apn_decode_segfault, 0);
	/* MSISDN */
	tcase_add_test (tc_core, test_gtpie_utils_msisdn_decode);
	tcase_add_test (tc_core, test_gtpie_utils_msisdn_encode);
	/* IMSI */
	tcase_add_test (tc_core, test_gtpie_utils_imsi_decode);
	tcase_add_test (tc_core, test_gtpie_utils_imsi_encode);
	/* TBCD */
	tcase_add_test (tc_core, test_gtpie_utils_tbcd_decode);
	tcase_add_test (tc_core, test_gtpie_utils_tbcd_encode);
	tcase_add_test (tc_core, test_gtpie_utils_tbcd_encode_0size);
	tcase_add_exit_test (tc_core, test_gtpie_utils_tbcd_decode_segfault, 0);
	suite_add_tcase (s, tc_core);

	return s;
}

Suite *
make_gtpie_utils_suite( void ){
	return gtpie_utils_suite ();
}

