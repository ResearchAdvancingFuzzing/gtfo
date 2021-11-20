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

#include "det_byte_arith.h"

#include "afl_config.h"
#include "common/types.h"
#include "mutate.h"
#include "strategy.h"

SERIALIZE_FUNC(det_byte_arith_serialize, "det_byte_arith")
PRINT_FUNC(det_byte_arith_print, "det_byte_arith")

#ifdef DET_BYTE_ARITH_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = det_byte_arith_populate;
#endif

static u8 could_be_bitflip(u32 xor_val) { 

    u32 sh = 0;
    if (!xor_val) return 1;

    /* Shift left until first bit set. */
    while (!(xor_val & 1)) { sh++; xor_val >>= 1; }

    /* 1-, 2-, and 4-bit patterns are OK anywhere. */
    if (xor_val == 1 || xor_val == 3 || xor_val == 15) return 1;

    /* 8-, 16-, and 32-bit patterns are OK only if shift factor is
       divisible by 8, since that's the stepover for these ops. */
    if (sh & 7) return 0;
    if (xor_val == 0xff || xor_val == 0xffff || xor_val == 0xffffffff)
        return 1;

    return 0;

}

    static inline size_t
det_byte_arith(u8 *buf, size_t size, strategy_state *state)
{
    u8 val;
    u8 r;
    u64 pos; 
    u8 result;
    do {
        u64 range_len = (MAX_ARITH * 2) + 1; // how many iterations per byte 
        pos       = state->iteration / range_len; // which byte we are mutating

        if (pos >= state->max_size) { 
            return 0;
        }
        
        u8 iter = (u8) (state->iteration % range_len); 
        u8 abs_val = (u8) ((iter + 1) / 2); 

        if ((iter + 1) % 2) { 
            // If iteration has remainder, we want to subtract 
            r = buf[pos] ^ (buf[pos]  - abs_val);
            val = -(abs_val);
        }
        else {
            r = buf[pos] ^ (buf[pos]  + abs_val);
            val = abs_val;  
        }
        // We want to do arithmetic operations only if the result couldn't
        // be a product of a bitflip 

        //printf("r: %d could_be_bitflip: %d\n", r, could_be_bitflip(r)); 
        result = could_be_bitflip(r); 
        if (result) { // skip this iteration
            state->iteration++; 
        }
    } while (result); 

    // Byte add
    byte_add(buf, pos, val);
    // printf("buf: %s\n", buf);

    // if edited outside of buf, extend buf's size.
    if (pos >= size) {
        size = pos + 1;
    }

    return size;
}

/* populates fuzzing_strategy structure */
    void
det_byte_arith_populate(fuzzing_strategy *strategy)
{
    strategy->version      = VERSION_ONE;
    strategy->name         = "det_byte_arith";
    strategy->create_state = strategy_state_create;
    strategy->mutate       = det_byte_arith;
    strategy->serialize    = det_byte_arith_serialize;
    strategy->deserialize  = strategy_state_deserialize;
    strategy->print_state  = det_byte_arith_print;
    strategy->copy_state   = strategy_state_copy;
    strategy->free_state   = strategy_state_free;
    strategy->description  = "Deterministically adds a number to a byte. "
        "This strategy iterates through the range {-MAX_ARITH, MAX_ARITH}. "
        "MAX_ARITH is defined in afl_config.h. "
        "It adds a single value from the range, depending on the iteration number. "
        "Once it is done iterating through the range, it moves to the next byte in the buffer and repeats.";
    strategy->update_state     = strategy_state_update;
    strategy->is_deterministic = true;
}
