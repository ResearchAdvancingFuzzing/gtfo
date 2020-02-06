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
#include "kvmcore/vcpu.h"
#include "nocturne_tap_helper.h"

bool kvm_vcpu_record_isequal(kvm_vcpu_record *r1, kvm_vcpu_record *r2);
void check_new_kvm_vcpu_record(kvm_vcpu_record *r);
void test_kvm_vcpu_record(void);

#define TEST_VCPU_RECORD_SUBSTRUCT_FIXEDSIZE(SUBSTRUCT_TYPE, SUBSTRUCT_NAME, SUBSTRUCT_FLAG, RECORD_FUNC) \
	do {                                                                                                  \
		struct SUBSTRUCT_TYPE foo;                                                                        \
		memset(&foo, 0x41, sizeof(struct SUBSTRUCT_TYPE));                                                \
		kvm_vcpu_record *r = kvm_vcpu_record_create();                                                    \
		RECORD_FUNC(r, &foo);                                                                             \
		if (!r->flags.SUBSTRUCT_FLAG) {                                                                   \
			ok(false, #SUBSTRUCT_FLAG "flag was set incorrectly by " #RECORD_FUNC ".");                   \
		} else {                                                                                          \
			ok(true, #SUBSTRUCT_FLAG " flag was set correctly by " #RECORD_FUNC ".");                     \
		}                                                                                                 \
		if (memcmp(&foo, &r->SUBSTRUCT_NAME, sizeof(struct SUBSTRUCT_TYPE))) {                            \
			ok(false, "struct " #SUBSTRUCT_TYPE " was recorded incorrectly by " #RECORD_FUNC ".");        \
		} else {                                                                                          \
			ok(true, "struct " #SUBSTRUCT_TYPE " was recorded correctly by " #RECORD_FUNC ".");           \
		}                                                                                                 \
		kvm_vcpu_record_free(r);                                                                          \
	} while (0);

#define TEST_VCPU_RECORD_SUBSTRUCT_VARSIZE(SUBSTRUCT_TYPE, SUBSTRUCT_NAME, SUBSTRUCT_FLAG, SUBSTRUCT_SIZE_FIELD, SUBSTRUCT_MEMBER_TYPE, SUBSTRUCT_MEMBER_NAME, NUM_MEMBERS, RECORD_FUNC) \
	do {                                                                                                                                                                                 \
		size_t                 substruct_size = sizeof(struct SUBSTRUCT_TYPE) + ((NUM_MEMBERS) * sizeof(struct SUBSTRUCT_MEMBER_TYPE));                                                    \
		struct SUBSTRUCT_TYPE *foo            = calloc(1, substruct_size);                                                                                                               \
		foo->SUBSTRUCT_SIZE_FIELD             = NUM_MEMBERS;                                                                                                                             \
		u8 i                                  = 0;                                                                                                                                       \
		for (; i < (NUM_MEMBERS); i++) {                                                                                                                                                   \
			memset(&foo->SUBSTRUCT_MEMBER_NAME[i], 0x61 + i, sizeof(struct SUBSTRUCT_MEMBER_TYPE));                                                                                      \
		}                                                                                                                                                                                \
		kvm_vcpu_record *r = kvm_vcpu_record_create();                                                                                                                                   \
		RECORD_FUNC(r, foo);                                                                                                                                                             \
		if (!r->flags.SUBSTRUCT_FLAG) {                                                                                                                                                  \
			ok(false, #SUBSTRUCT_FLAG " flag was set incorrectly by " #RECORD_FUNC ".");                                                                                                 \
		} else {                                                                                                                                                                         \
			ok(true, #SUBSTRUCT_FLAG " flag was set correctly by " #RECORD_FUNC ".");                                                                                                    \
		}                                                                                                                                                                                \
		if (memcmp(foo, r->SUBSTRUCT_NAME, sizeof(struct SUBSTRUCT_TYPE))) {                                                                                                             \
			ok(false, "struct " #SUBSTRUCT_TYPE " was recorded incorrectly by " #RECORD_FUNC ".");                                                                                       \
		} else {                                                                                                                                                                         \
			ok(true, "struct " #SUBSTRUCT_TYPE " was recorded correctly by " #RECORD_FUNC ".");                                                                                          \
		}                                                                                                                                                                                \
		kvm_vcpu_record_free(r);                                                                                                                                                         \
		free(foo);                                                                                                                                                                       \
	} while (0);
