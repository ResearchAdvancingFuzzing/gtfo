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
#include "nocturne_tap_helper.h"
#include "kvm_engine_tap.h"
#include "intel_pt/vcpu_pt.h"


#define SIMPLE_TAP_TEST(CONDITION, DESCRIPTION) \
do {\
    if((CONDITION)) {\
        ok(true, DESCRIPTION);\
    } else { \
        ok(false, DESCRIPTION); \
    }\
} while(0);

void test_kvm_vcpu_pt_mark_should_enable(kvm_vcpu_pt *vcpu_pt);
void test_kvm_vcpu_pt_mark_should_not_enable(kvm_vcpu_pt *vcpu_pt);
void test_kvm_vcpu_pt_default_config(kvm_vcpu_pt *vcpu_pt);
void test_kvm_vcpu_pt_create(kvm_vcpu_pt * vcpu_pt);
