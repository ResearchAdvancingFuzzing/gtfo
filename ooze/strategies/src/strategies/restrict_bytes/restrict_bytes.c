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

#include "restrict_bytes.h"

#include <stdlib.h>
#include <string.h>
#include <dlfcn.h> 
#include <stdio.h>
#include <stdint.h>

#include "common/types.h"
#include "common/logger.h"
#include "mutate.h"
#include "strategy.h"

// Used to hold on to the actual strategy we are using 
static void *strategy_lib = NULL; 
static strategy_state *strat_state = NULL; 
static fuzzing_strategy strat; 
// Holds the fbs 
static int *fbs = NULL;
static size_t num_labels; 

#ifdef RESTRICT_BYTES_IS_MASTER
get_fuzzing_strategy_function get_fuzzing_strategy = restrict_bytes_populate;
#endif

// update the restrict_bytes strategy state.
    static inline void
restrict_bytes_update(strategy_state *state)
{
    strat.update_state(strat_state); 
    strategy_state_update(state);
}

// serialize the restrict_bytes strategy state.
    static inline char *
restrict_bytes_serialize(strategy_state *state)
{
    return strategy_state_serialize(state, "restrict_bytes");
}

// deserialize the restrict_bytes strategy state.
    static inline strategy_state *
restrict_bytes_deserialize(char *s_state, size_t s_state_size)
{
    return strategy_state_deserialize(s_state, s_state_size);
}

// create a human-readable string that describes the strategy state.
    static inline char *
restrict_bytes_print(strategy_state *state)
{
    char *p_strat_state = strat.print_state(strat_state); 
    char *p_state   = strategy_state_print(state, "restrict_bytes");
    char *char_fbs = (char*) malloc(sizeof(char) * (num_labels + 1));
    int i;
    for (i = 0; i < (int) num_labels; i++)  
        char_fbs[i] = (char) fbs[i]; // + '0'; 
    char_fbs[num_labels-1] = '\n'; 

    //combine them into one buffer!
    char *p_both = calloc(1, strlen(p_strat_state) + strlen(p_state) + strlen(char_fbs) + 1);

    strcat(p_both, p_strat_state);
    strcat(p_both, p_state);
    strcat(p_both, char_fbs);

    // don't need these anymore
    free(p_strat_state); 
    free(p_state);
    free(char_fbs);

    return p_both;
}


static void * load_module(char *module_name) {
    //printf("module_name: %s\n", module_name); 
    void * handle = NULL;
    handle = dlopen(module_name, RTLD_LAZY);
    
    char *error = dlerror();
    if (error) 
        log_fatal(error); 
    if (handle == NULL) 
        log_fatal("Couldn't open module: %s", module_name); 

    return handle;
}

// create a restrict_bytes strategy_state object.
    static inline strategy_state *
restrict_bytes_create(u8 *seed, size_t max_size, ...)
{
    strategy_state *new_state = strategy_state_create(seed, max_size);

    char *env_ooze_strategy = getenv("OOZE_MODULE_NAME"); 
    if (env_ooze_strategy == NULL) {
        log_fatal("Missing OOZE_MODULE_NAME environment variable");
    }
    char * ooze_strategy = env_ooze_strategy; 

    char *env_labels = getenv("OOZE_LABELS"); 
    if (env_labels == NULL) { 
        log_fatal("Missing OOZE_LABELS envrionment variable"); 
    }

    char *env_num_labels = getenv("OOZE_LABELS_SIZE"); 
    if (env_num_labels == NULL) {
        log_fatal("Missing OOZE_LABELS_SIZE environment variable"); 
    }
    num_labels = (size_t) atoi(env_num_labels); 

    //printf("Num labels: %lu\n", num_labels); 
    //printf("Ooze labels: %s\n", env_labels); 

    fbs = (int*) malloc(sizeof(int) * num_labels); 
    
    char delim[] = ","; 
    char *ptr = strtok(env_labels, delim); 
    int i = 0; 
    while (ptr != NULL) { 
        fbs[i++] = atoi(ptr);  
        ptr = strtok(NULL, delim); 
    }
    for (i = 0; i < (int) num_labels; i++) { 
        printf("%d\n", fbs[i]); 
    }

    // Get the strategy lib 
    strategy_lib = load_module(ooze_strategy); 
    get_fuzzing_strategy_function *get_fuzzing_strategy_ptr = dlsym(strategy_lib, "get_fuzzing_strategy"); 
    char* error = dlerror(); 
    if (error) log_fatal(error); 
    (*get_fuzzing_strategy_ptr)(&strat); 
    
    strat_state = strat.create_state(seed, max_size, 0, 0, 0);  
    return new_state;
}

// free a restrict_bytes strategy_state object.
    static inline void
restrict_bytes_free(strategy_state *state)
{

    free(fbs); 
    state->internal_state = NULL;
    strategy_state_free(state);
    strat.free_state(strat_state); 
}

// copy a restrict_bytes strategy_state object.
    static inline strategy_state *
restrict_bytes_copy(strategy_state *state)
{
    return strategy_state_copy(state);
}

    static inline size_t
restrict_bytes(u8 *buf, size_t size, strategy_state *state)
{
    if (size >= state->max_size)
        return 0; 
    // Make sure that the fbs labels are within the buf range
    int i;
    for (i = 0; i < (int) num_labels; i++) {
        if (fbs[i] >= (int) size) 
            return 0; 
    }

    // Make the new byte buffer from the fbs and the buf
    u8 *new_buf; 
    new_buf = malloc(sizeof(u8) * num_labels); 
    for (i = 0; i < (int) num_labels; i++) {
        new_buf[i] = buf[fbs[i]];
        //printf("%d ", new_buf[i]); 
    }

    // Mutate the buffer
    size = strat.mutate(new_buf, num_labels, strat_state); 
    if (size == 0) 
        return 0;
    
    // Update the original buffer 
    //printf("New Buffer\n"); 
    for (i = 0; i < (int) num_labels; i++){
        buf[fbs[i]] = new_buf[i];
        //printf("%d ", new_buf[i]); 
    }
    
    return size;
    
}

/* populates fuzzing_strategy structure */
    void
restrict_bytes_populate(fuzzing_strategy *strategy)
{
    strategy->version          = VERSION_ONE;
    strategy->name             = "restrict_bytes";
    strategy->create_state     = restrict_bytes_create;
    strategy->mutate           = restrict_bytes;
    strategy->serialize        = restrict_bytes_serialize;
    strategy->deserialize      = restrict_bytes_deserialize;
    strategy->print_state      = restrict_bytes_print;
    strategy->copy_state       = restrict_bytes_copy;
    strategy->free_state       = restrict_bytes_free;
    strategy->description      = "restricts mutations to bytes within the fbs";
    strategy->update_state     = restrict_bytes_update;
    strategy->is_deterministic = true;

}
