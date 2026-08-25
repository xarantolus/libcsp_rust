/* Runner for the C oracle.
 *
 * Kept a plain executable rather than folded into a Rust build step so that libcheck's
 * own environment knobs still work: CK_RUN_SUITE=RDP to run one suite, CK_RUN_CASE to
 * run one test, CK_FORK=no to run under gdb.
 *
 * Fork-per-test is left on deliberately. It is what lets every test call csp_init(),
 * and it isolates the process-global state libcsp keeps: the RDP option statics and
 * csp_rdp_incr, the dedup array, csp_conf, and the interface list.
 *
 * So CK_FORK=no only works one test at a time. Run the whole binary that way and the
 * second test to call csp_promisc_enable() gets CSP_ERR_NOMEM, because the queue from
 * the first is still registered. Pair it with CK_RUN_CASE.
 */
#include "trace.h"

#include <check.h>
#include <getopt.h>
#include <stdio.h>
#include <stdlib.h>

Suite * queue_suite(void);
Suite * buffer_suite(void);
Suite * hmac_suite(void);
Suite * rdp_suite(void);
Suite * promisc_suite(void);
Suite * dedup_suite(void);
Suite * security_suite(void);
Suite * cmp_suite(void);
Suite * eth_suite(void);
Suite * sfp_suite(void);
Suite * conn_suite(void);

static struct option long_options[] = {
	{"verbose", no_argument, 0, 'V'},
	{"trace", required_argument, 0, 't'},
	{"help", no_argument, 0, 'h'},
	{0, 0, 0, 0},
};

static void print_help(void) {
	printf("Usage: ctest [options]\n");
	printf("Run the C oracle suites against the real libcsp.\n\n");
	printf("  -V, --verbose      print each test as it runs\n");
	printf("  -t, --trace PATH   record what the C did, as JSON Lines\n");
	printf("  -h, --help         print this help\n\n");
	printf("Environment: CK_FORK=no, CK_RUN_SUITE=<name>, CK_RUN_CASE=<name>\n");
}

int main(int argc, char * argv[]) {
	enum print_output verbosity = CK_NORMAL;
	const char * trace_path = NULL;
	int opt;

	while ((opt = getopt_long(argc, argv, "Vt:h", long_options, NULL)) != -1) {
		switch (opt) {
			case 'V':
				verbosity = CK_VERBOSE;
				break;
			case 't':
				trace_path = optarg;
				break;
			case 'h':
				print_help();
				return EXIT_SUCCESS;
			default:
				print_help();
				return EXIT_FAILURE;
		}
	}

	/* Opened before any test forks, so every child inherits the descriptor and appends to
	 * the same file. */
	ctest_trace_open(trace_path);

	SRunner * sr = srunner_create(NULL);
	srunner_add_suite(sr, queue_suite());
	srunner_add_suite(sr, buffer_suite());
	srunner_add_suite(sr, hmac_suite());
	srunner_add_suite(sr, rdp_suite());
	srunner_add_suite(sr, promisc_suite());
	srunner_add_suite(sr, dedup_suite());
	srunner_add_suite(sr, security_suite());
	srunner_add_suite(sr, cmp_suite());
	srunner_add_suite(sr, eth_suite());
	srunner_add_suite(sr, sfp_suite());
	srunner_add_suite(sr, conn_suite());

	srunner_run_all(sr, verbosity);
	int failed = srunner_ntests_failed(sr);
	srunner_free(sr);

	return (failed == 0) ? EXIT_SUCCESS : EXIT_FAILURE;
}
