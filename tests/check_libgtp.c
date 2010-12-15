#include <stdlib.h>
#include <stdio.h>

#include <inttypes.h>
#include <netinet/in.h>
#include "../gtp/pdp.h"
#include "../gtp/gtp.h"
#include "../gtp/gtpie.h"
#include "check_libgtp.h"


START_TEST (test_pdpctxresp_decap)
{
	/**
   * End user IP 192.168.1.100 (0xC0A8017B)
   * DNS 192.168.2.2/192.168.2.3 (0xC0A80202/C0A80203)
   * GSN Address 192.168.3.123/192.168.3.124 (0xC0A8037B/C0A8037C)
   */
/*
	u_char gp[] = {
0x32, 0x11, 0x00, 0x62, 0x11, 0x1a, 0x72, 0x91,
0x9e, 0x8a, 0x00, 0x00, */
	u_char gp[] = { 0x01, 0x80, 0x08, 0xfe,
0x10, 0x00, 0x00, 0x28, 0x83, 0x11, 0x00, 0x00,
0x28, 0x83, 0x7f, 0x00, 0x06, 0x7d, 0xe6, 0x80,
0x00, 0x06, 0xf1, 0x21, 0xc0, 0xa8, 0x01, 0x7b,
0x84, 0x00, 0x1b, 0x80, 0xc2, 0x23, 0x04, 0x03,
0x00, 0x00, 0x04, 0x80, 0x21, 0x10, 0x03, 0x00,
0x00, 0x10, 0x81, 0x06, 0xc0, 0xa8, 0x02, 0x02,
0x83, 0x06, 0xc0, 0xa8, 0x02, 0x03, 0x85, 0x00,
0x04, 0xc0, 0xa8, 0x03, 0x7b, 0x85, 0x00, 0x04,
0xc0, 0xa8, 0x03, 0x7c, 0x87, 0x00, 0x0c, 0x01,
0x0d, 0x91, 0x1f, 0x73, 0x0a, 0x96, 0xf4, 0x43,
0x49, 0x01, 0x01, 0xfb, 0x00, 0x04, 0x7f, 0x00,
0x00, 0x01 };

	uint8_t *_cause = gp+1;
	uint32_t *_tei_di = gp+5;
	uint32_t *_tei_c = gp+10;
	uint32_t tei_di, tei_c;
	uint8_t cause;
	union gtpie_member* ie[GTPIE_SIZE];
	/* decap */
	fail_unless( gtpie_decaps (ie, 1, gp, sizeof (gp)) == 0, "Failed to decapsulate GTP packet");
	/* cause */
	fail_unless( gtpie_exist (ie, GTPIE_CAUSE, 0) == 1, "Failed to find GTPIE_CAUSE");
	fail_unless( gtpie_gettv1 (ie, GTPIE_CAUSE, 0, &cause) == 0, "Error getting GTPIE_CAUSE");
	fail_unless( cause == *_cause, "Cause has value %d while %d is expected", cause, *_cause);

	/* TEI DI */
	fail_unless( gtpie_exist (ie, GTPIE_TEI_DI, 0) == 1, "Failed to find GTPIE_TEI_DI");
	fail_unless( gtpie_gettv4 (ie, GTPIE_TEI_DI, 0, &tei_di) == 0, "Error getting GTPIE_TEI_DI");
	fail_unless( tei_di == ntohl(*_tei_di), "TEI DI has value 0x%.8"PRIX32" while 0x%.8"PRIX32" is expected", tei_di, ntohl(*_tei_di));

	/* TEI C */
	fail_unless( gtpie_exist (ie, GTPIE_TEI_C, 0) == 1, "Failed to find GTPIE_TEI_C");
	fail_unless( gtpie_gettv4 (ie, GTPIE_TEI_C, 0, &tei_c) == 0, "Error getting GTPIE_TEI_C");
	fail_unless( tei_c == ntohl(*_tei_c), "TEI C has value 0x%.8"PRIX32" while 0x%.8"PRIX32" is expected", tei_c, ntohl(*_tei_c));

}
END_TEST


Suite *
make_libgtp_suite (void){
	Suite *s = suite_create ("LIB GTP");

	/* Core test case */
	TCase *tc_core = tcase_create ("Core");
	/* DECAPS */
	tcase_add_test (tc_core, test_pdpctxresp_decap);


	suite_add_tcase (s, tc_core);

	return s;
}


