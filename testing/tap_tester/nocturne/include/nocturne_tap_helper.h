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

#pragma once
#include "tap.h"

#define TEST_SUBSTRUCT_FUNC(KVM_STRUCT_TYPE, SUBSTRUCT_NAME, SUBSTRUCT_FLAG, SUBSTRUCT_TYPE, SUBSTRUCT_FUNC) \
	do {                                                                                                     \
		diagnostics("Testing function " #SUBSTRUCT_FUNC);                                                    \
        KVM_STRUCT_TYPE *s = calloc(1, sizeof(KVM_STRUCT_TYPE));                                             \
		SUBSTRUCT_TYPE   substruct;                                                                          \
		memset(&substruct, 0, sizeof(SUBSTRUCT_TYPE));                                                       \
		SUBSTRUCT_FUNC(s, substruct);                                                                        \
		if (s->flags.SUBSTRUCT_FLAG) {                                                                       \
			ok(true, "function set present flag correctly.");                                                \
			if (memcmp(&s->SUBSTRUCT_NAME, &substruct, sizeof(SUBSTRUCT_TYPE)) != 0) {                            \
				ok(false, "data mismatch!");                                                                 \
			} else {                                                                                         \
				ok(true, "function is behaving correctly.");                                                 \
			}                                                                                                \
		} else {                                                                                             \
			ok(false, "function did not set present flag.");                                                 \
		}                                                                                                    \
		free(s);                                                                                             \
	} while (0);

#define TEST_KVM_SUBSTRUCT_FUNC(KVM_STRUCT_TYPE, SUBSTRUCT_NAME, SUBSTRUCT_FLAG, SUBSTRUCT_TYPE, SUBSTRUCT_FUNC) \
	do {                                                                                                         \
		diagnostics("Testing function " #SUBSTRUCT_FUNC);                                                        \
		KVM_STRUCT_TYPE *     s = calloc(1, sizeof(KVM_STRUCT_TYPE));                                            \
		struct SUBSTRUCT_TYPE substruct;                                                                         \
		memset(&substruct, 0, sizeof(struct SUBSTRUCT_TYPE));                                                    \
		SUBSTRUCT_FUNC(s, &substruct);                                                                           \
		if (s->flags.SUBSTRUCT_FLAG) {                                                                           \
			ok(true, "function set present flag correctly.");                                                    \
			if (memcmp(&s->SUBSTRUCT_NAME, &substruct, sizeof(struct SUBSTRUCT_TYPE)) != 0) {                         \
				ok(false, "data mismatch!");                                                                     \
			} else {                                                                                             \
				ok(true, "function is behaving correctly.");                                                     \
			}                                                                                                    \
		} else {                                                                                                 \
			ok(false, "function did not set present flag.");                                                     \
		}                                                                                                        \
		free(s);                                                                                                 \
	} while (0);

#define TEST_KVM_PSUBSTRUCT_FUNC(KVM_STRUCT_TYPE, SUBSTRUCT_NAME, SUBSTRUCT_FLAG, SUBSTRUCT_TYPE, SUBSTRUCT_FUNC) \
	do {                                                                                                          \
		diagnostics("Testing function " #SUBSTRUCT_FUNC);                                                         \
		KVM_STRUCT_TYPE *      s         = calloc(1, sizeof(struct KVM_STRUCT_TYPE));                             \
		struct SUBSTRUCT_TYPE *substruct = calloc(1, sizeof(struct SUBSTRUCT_TYPE));                              \
		SUBSTRUCT_FUNC(s, substruct);                                                                             \
		if (s->flags.SUBSTRUCT_FLAG) {                                                                            \
			ok(true, "function set present flag correctly.");                                                     \
			if (memcmp(s->SUBSTRUCT_NAME, substruct, sizeof(struct SUBSTRUCT_TYPE)) != 0) {                            \
				ok(false, "data mismatch!");                                                                      \
			} else {                                                                                              \
				ok(true, "function is behaving correctly.");                                                      \
			}                                                                                                     \
		} else {                                                                                                  \
			ok(false, "function did not set present flag.");                                                      \
		}                                                                                                         \
		free(s->SUBSTRUCT_NAME);                                                                                  \
		free(substruct);                                                                                          \
		free(s);                                                                                                  \
	} while (0);

#define TEST_TAILQ_RECORD(PSTRUCT, TAILQ_HEAD, TAILQ_CTR, NODE_TYPE, PRESENT_FLAG, SUBSTRUCT_NAME, SUBSTRUCT_TYPE, NODE_COUNT, RECORD_FUNC) \
	do {                                                                                                                                    \
		diagnostics("Testing " #NODE_TYPE " TAILQ of " #NODE_COUNT " Nodes.");                                                              \
		u32 i = 0;                                                                                                                          \
		for (; i < (NODE_COUNT); i++) {                                                                                                       \
			struct SUBSTRUCT_TYPE *substruct = calloc(1, sizeof(struct SUBSTRUCT_TYPE));                                                    \
			memset(substruct, 0x41 + (u8)i, sizeof(struct SUBSTRUCT_TYPE));                                                                 \
			RECORD_FUNC(PSTRUCT, substruct);                                                                                                \
			free(substruct);                                                                                                                \
		}                                                                                                                                   \
		if ((PSTRUCT)->TAILQ_CTR != (NODE_COUNT)) {                                                                                             \
			ok(false, "node count mismatch!");                                                                                              \
		} else {                                                                                                                            \
			ok(true, "node count matched!");                                                                                                \
		}                                                                                                                                   \
		if (!(PSTRUCT)->flags.PRESENT_FLAG) {                                                                                                 \
			ok(false, "Present flag not set!");                                                                                             \
		} else {                                                                                                                            \
			ok(true, "Present flag set correctly!");                                                                                        \
		}                                                                                                                                   \
		i              = 0;                                                                                                                 \
        NODE_TYPE *itr = NULL;                                                                                                              \
		TAILQ_FOREACH(itr, &(PSTRUCT)->TAILQ_HEAD, record_list)                                                                               \
		{                                                                                                                                   \
			struct SUBSTRUCT_TYPE placeholder;                                                                                              \
			memset(&placeholder, 0x41 + (u8)i, sizeof(struct SUBSTRUCT_TYPE));                                                              \
			if (memcmp(&itr->SUBSTRUCT_NAME, &placeholder, sizeof(struct SUBSTRUCT_TYPE)) != 0) {                                                \
				ok(false, "node data mismatch!");                                                                                           \
			} else {                                                                                                                        \
				ok(true, "node data match!");                                                                                               \
			}                                                                                                                               \
			i++;                                                                                                                            \
		}                                                                                                                                   \
	} while (0);

#define TEST_TAILQ_UNRECORD(KVM_PSTRUCT, TAILQ_CTR, PRESENT_FLAG, SUBSTRUCT_TYPE, UNRECORD_FUNC, HELPER_FUNC) \
	do {                                                                                                      \
		diagnostics("Testing " #UNRECORD_FUNC);                                                               \
		u64 i        = 0;                                                                                     \
		u64 orig_ctr = (KVM_PSTRUCT)->TAILQ_CTR;                                                                \
		for (; i < orig_ctr; i++) {                                                                           \
			struct SUBSTRUCT_TYPE placeholder;                                                                \
			memset(&placeholder, 0x41 + (u8)i, sizeof(struct SUBSTRUCT_TYPE));                                \
			HELPER_FUNC(&placeholder);                                                                        \
			UNRECORD_FUNC(KVM_PSTRUCT, &placeholder);                                                         \
		}                                                                                                     \
		if ((KVM_PSTRUCT)->TAILQ_CTR != 0) {                                                                    \
			ok(false, "node counter value mismatch!");                                                        \
		} else {                                                                                              \
			ok(true, "node counter value match! all nodes removed!");                                         \
		}                                                                                                     \
		if ((KVM_PSTRUCT)->flags.PRESENT_FLAG) {                                                                \
			ok(false, "Present flag not cleared!");                                                           \
		} else {                                                                                              \
			ok(true, "Present flag cleared correctly!");                                                      \
		}                                                                                                     \
	} while (0);

#define TAILQ_COMPARE_FIXEDSIZE(TAILQ_HEAD1, TAILQ_HEAD2, NODE_TYPE, SUBSTRUCT_TYPE, SUBSTRUCT_NAME, RETVAL) \
	do {                                                                                                     \
        (RETVAL)          = true;                                                                              \
        NODE_TYPE *itr1 = TAILQ_FIRST(&(TAILQ_HEAD1));                                                         \
        NODE_TYPE *itr2 = TAILQ_FIRST(&(TAILQ_HEAD2));                                                         \
		while (itr1 && itr2) {                                                                               \
			if (memcmp(&itr1->SUBSTRUCT_NAME, &itr2->SUBSTRUCT_NAME, sizeof(struct SUBSTRUCT_TYPE)) != 0) {       \
				(RETVAL) = false;                                                                              \
				break;                                                                                       \
			}                                                                                                \
			itr1 = TAILQ_NEXT(itr1, record_list);                                                            \
			itr2 = TAILQ_NEXT(itr2, record_list);                                                            \
		}                                                                                                    \
		if (itr1 != NULL) {                                                                                  \
			(RETVAL) = false;                                                                                  \
		} else if (itr2 != NULL) {                                                                           \
			(RETVAL) = false;                                                                                  \
		}                                                                                                    \
	} while (0);
