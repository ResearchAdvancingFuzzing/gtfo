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

#include "kvm_vcpu_pt_tap.h"
#include <intel_pt/vcpu_pt.h>

//This file contains any unit tests that involve directly reaching into a kvm_vcpu_pt object

void
test_kvm_vcpu_pt_mark_should_enable(kvm_vcpu_pt *vcpu_pt)
{
    SIMPLE_TAP_TEST(vcpu_pt->status.configured_to_be_enabled && vcpu_pt->status.should_enable, "test_kvm_vcpu_pt_mark_should_enable: status flag check.")
}

void
test_kvm_vcpu_pt_mark_should_not_enable(kvm_vcpu_pt *vcpu_pt)
{
    SIMPLE_TAP_TEST(!vcpu_pt->status.should_enable, "test_kvm_vcpu_pt_mark_should_not_enable: status flag check.")
}

void
test_kvm_vcpu_pt_default_config(kvm_vcpu_pt *vcpu_pt)
{
    bool addr_range_configured = false;
    int itr = 0;
    for(; itr < 4; itr++){
        if(vcpu_pt->selectors.addr_range[itr].enabled){
            addr_range_configured = true;
            break;
        }
    }
    if(
        addr_range_configured ||
        //!vcpu_pt->selectors.cr3.enabled ||
        !vcpu_pt->selectors.ring_0.enabled ||
        !vcpu_pt->selectors.ring_3.enabled ||
        !vcpu_pt->status.configured_to_be_enabled
        ) {
        ok(false, "test_kvm_vcpu_pt_default_config: Default configuration was incorrect.");
    } else {
        ok(true, "test_kvm_vcpu_pt_default_config: Default configuration was correct.");
    }
}

void
test_kvm_vcpu_pt_create(kvm_vcpu_pt * vcpu_pt)
{
    SIMPLE_TAP_TEST(vcpu_pt, "test_kvm_vcpu_pt_create: return value.")
    SIMPLE_TAP_TEST(vcpu_pt->vcpu, "test_kvm_vcpu_pt_create: vcpu pointer initialization.")
    SIMPLE_TAP_TEST(!vcpu_pt->status.should_enable, "test_kvm_vcpu_pt_create: should_enable status bit.")
    SIMPLE_TAP_TEST(!vcpu_pt->status.enabled, "test_kvm_vcpu_pt_create: enabled status bit.")
    SIMPLE_TAP_TEST(vcpu_pt->topa_region, "test_kvm_vcpu_pt_create: topa_region allocation.")
    SIMPLE_TAP_TEST(vcpu_pt->trace_data, "test_kvm_vcpu_pt_create: trace_data buffer allocation.")
    SIMPLE_TAP_TEST(!vcpu_pt->trace_data_size, "test_kvm_vcpu_pt_create: trace_data_size value.")

}

