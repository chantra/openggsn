
#include <stdlib.h>

#ifdef ENABLE_GTPDUMP
#include "check_gtpie_utils.h"
#endif

#include "check_libgtp.h"



int main (void){
	int number_failed;

	Suite *s = make_libgtp_suite ();
	SRunner *sr = srunner_create (s);
#ifdef ENABLE_GTPDUMP
	srunner_add_suite (sr, make_gtpie_utils_suite ());
#endif
	srunner_run_all (sr, CK_NORMAL);
	number_failed = srunner_ntests_failed (sr);
	srunner_free (sr);
	return (number_failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}

