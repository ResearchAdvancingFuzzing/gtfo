// DISTRIBUTION STATEMENT A. Approved for public release. Distribution is unlimited.
//
// This material is based upon work supported by the Department of the Air Force under Air Force Contract No. FA8702-15-D-0001. Any opinions, findings, conclusions or recommendations expressed in this material are those of the author(s) and do not necessarily reflect the views of the Department of the Air Force.
//
// © 2019 Massachusetts Institute of Technology.
//
// Subject to FAR52.227-11 Patent Rights - Ownership by the contractor (May 2014)
//
// The software/firmware is provided to you on an As-Is basis
//
// Delivered to the U.S. Government with Unlimited Rights, as defined in DFARS Part 252.227-7013 or 7014 (Feb 2014). Notwithstanding any copyright notice, U.S. Government rights in this work are defined by DFARS 252.227-7013 or DFARS 252.227-7014 as detailed above. Use of this work other than as specifically authorized by the U.S. Government may violate any copyrights that exist in this work.

#include <stdlib.h>
#include <string.h>

#include "jig.h"
#include "common/types.h"

static unsigned char ___test_data_intelpt_loop_tnt_pt[] = {
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
    0x02, 0x82, 0x02, 0x82, 0x7d, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x99,
    0x01, 0x02, 0x23, 0x1c, 0x7d, 0x13, 0x00, 0x10, 0x00, 0x00, 0x00, 0x01};
static unsigned int ___test_data_intelpt_loop_tnt_pt_len = 36;

static unsigned char ___test_data_intelpt_loop_tnt_tnt_pt[] = {
    0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82, 0x02, 0x82,
    0x02, 0x82, 0x02, 0x82, 0x7d, 0x00, 0x00, 0x10, 0x00, 0x00, 0x00, 0x99,
    0x01, 0x02, 0x23, 0xfe, 0x1c, 0x7d, 0x13, 0x00, 0x10, 0x00, 0x00, 0x00,
    0x01};
static unsigned int ___test_data_intelpt_loop_tnt_tnt_pt_len = 37;

static u8 *results_buf = NULL;

static void
init()
{
}

static char *
run(u8 *input, size_t input_size, u8 **results, size_t *results_size)
{
	if (!results_buf) {
		results_buf = calloc(100, 1);
		*results    = results_buf;
	}
	memcpy(*results, ___test_data_intelpt_loop_tnt_pt, ___test_data_intelpt_loop_tnt_pt_len);
	*results_size = ___test_data_intelpt_loop_tnt_pt_len;

	if (memcmp(input, "helln", input_size) == 0) {
		return CRASH;
	}

	if (memcmp(input, "xello", input_size) == 0) {
		memcpy(*results, ___test_data_intelpt_loop_tnt_tnt_pt, ___test_data_intelpt_loop_tnt_tnt_pt_len);
		*results_size = ___test_data_intelpt_loop_tnt_tnt_pt_len;
	}
	return NULL;
}
static void
destroy()
{
	free(results_buf);
}

static void
create_api(jig_api *j)
{
	j->version     = VERSION_ONE;
	j->name        = "dummy jig";
	j->description = "This is for testing.";
	j->initialize  = init;
	j->run         = run;
	j->destroy     = destroy;
}

jig_api_getter get_jig_api = create_api;
