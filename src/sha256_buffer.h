#ifndef SHA256_BUFFER_H
#define SHA256_BUFFER_H

#include <stdint.h>
#include <stddef.h>

#define NUM_HASHES (6*50000000)
#define USED_HASHES (NUM_HASHES / 300)
#define PARAM_COUNT (692)
#define PARAM_ALLOC (PARAM_COUNT * USED_HASHES * sizeof(uint32_t))
#define TARGET_ALLOC (USED_HASHES * sizeof(uint32_t))

struct ctx_type {
    int fd_len, fd_data;
    uint8_t *lengths;
    uint8_t *data;
    uint32_t *inputBuffer, *targetBuffer;
    uint32_t *secondInputBuffer, *secondTargetBuffer;
    size_t hash_offset, data_offset;
    uint32_t secondBuffer;
};

extern struct ctx_type ctx;

void init();
void nextData();
void shutdown();

#endif
