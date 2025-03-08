#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <stdbool.h>
#include <fcntl.h>
#include <sys/mman.h>
#include <sys/stat.h>
#include <unistd.h>
#include <pthread.h>
#include <stdatomic.h>

#define NUM_HASHES (50000000*6)
#define USED_HASHES (NUM_HASHES / 300)
#define PARAM_COUNT (692)
#define PARAM_ALLOC (PARAM_COUNT * USED_HASHES * sizeof(uint32_t))
#define TARGET_ALLOC (USED_HASHES * sizeof(uint32_t))

#define ROTR(x, n) (((x) >> (n)) | ((x) << (32 - (n))))
#define Σ0(x) (ROTR((x), 2) ^ ROTR((x), 13) ^ ROTR((x), 22))
#define Σ1(x) (ROTR((x), 6) ^ ROTR((x), 11) ^ ROTR((x), 25))
#define σ0(x) (ROTR((x), 7) ^ ROTR((x), 18) ^ ((x) >> 3))
#define σ1(x) (ROTR((x), 17) ^ ROTR((x), 19) ^ ((x) >> 10))
#define Ch(x, y, z) (((x) & (y)) ^ (~(x) & (z)))
#define Maj(x, y, z) (((x) & (y)) ^ ((x) & (z)) ^ ((y) & (z)))

#define PUSH(condition, ...) if(condition) { \
    uint32_t* ptr = (ctx.secondBuffer ? ctx.secondInputBuffer : ctx.inputBuffer) + (hashIndex * PARAM_COUNT) + featureIndex; \
    uint32_t data[] = { __VA_ARGS__ }; \
    memcpy(ptr, data, sizeof(data)); \
    featureIndex += sizeof(data) / sizeof(data[0]); \
}

/*#define PUSH(condition, ...) if(condition) { \
    uint32_t data[] = { __VA_ARGS__ };\
    pushIdx += sizeof(data) / 4;\
}*/


static const uint32_t K[64] = {
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
};

struct {
    int fd_len, fd_data;
    uint8_t *lengths;
    uint8_t *data;
    uint32_t *inputBuffer, *targetBuffer;
    uint32_t *secondInputBuffer, *secondTargetBuffer;
    size_t hash_offset, data_offset;
    uint32_t secondBuffer;
} ctx;
struct stat st_len, st_data;
pthread_t loader_thread;

pthread_mutex_t buffer_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t buffer_ready = PTHREAD_COND_INITIALIZER;

pthread_mutex_t next_lock = PTHREAD_MUTEX_INITIALIZER;
pthread_cond_t next_ready = PTHREAD_COND_INITIALIZER;
volatile atomic_int buffer_loaded = 0;

static inline uint32_t sha256(const uint8_t *msg, size_t length, uint32_t hashIndex) {
    uint64_t bit_length = length * 8;
    uint8_t withPad[64] = {0};
    memcpy(withPad, msg, length);
    withPad[length] = 0x80;

    size_t i = length + 1;
    while ((i * 8) % 512 != 448) {
        withPad[i++] = 0;
    }

    for (int j = 7; j >= 0; j--) {
        withPad[i++] = (bit_length >> (j * 8)) & 0xFF;
    }

    uint32_t W[64];
    for (int j = 0; j < 16; j++) {
        W[j] = (withPad[j * 4] << 24) | (withPad[j * 4 + 1] << 16) | (withPad[j * 4 + 2] << 8) | (withPad[j * 4 + 3]);
    }
    for (int j = 16; j < 64; j++) {
        W[j] = σ1(W[j - 2]) + W[j - 7] + σ0(W[j - 15]) + W[j - 16];
    }

    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a, e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    uint16_t featureIndex = 0;

    //uint32_t pushIdx = 0;

    uint32_t T1Before = 0, T2Before = 0;
    for (int j = 0; j < 64; j++) {
        uint32_t T1 = h + Σ1(e) + Ch(e, f, g) + K[j] + W[j];
        uint32_t T2 = Σ0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;

        PUSH(j >= 56, a, Σ0(a), Σ1(a), -a, ~a, -Σ0(a), ~Σ0(a), -Σ1(a), ~Σ1(a), 
        Σ0(a)-Σ1(a), Σ1(a)-Σ0(a), Σ1(a) ^ Σ0(a), Σ1(a) | Σ0(a), Σ1(a) % Σ0(a), Σ0(a) % Σ1(a), Σ1(a)/Σ0(a), Σ0(a)/Σ1(a));
        PUSH(j >= 57, a-b, b-a, a ^ b, a | b, a % b, b % a, a/b, b/a);
        PUSH(j >= 58, Maj(a, b, c), -Maj(a, b, c), ~Maj(a, b, c));
        PUSH(j >= 59, T1, T2, -T1, -T2, ~T1, ~T2, T1 - T2, T1 ^ T2, T1 & T2, T1 | T2, a ^ T2, a & T2, a | T2, a % T2, T1 ^ a,
                      T1 & a, T1 | a, T1 % a, T1 - b, T1 ^ b, T1 & b, T1 | b, T1 % b, T1/b, b/T1, T2 - b, T2 ^ b, T2 & b, T2 | b, T2 % b, T2/b, b/T2);

        PUSH(j >= 60, e, Σ0(e), Σ1(e), -e, ~e, -Σ0(e), ~Σ0(e), -Σ1(e), ~Σ1(e), 
        Σ0(e)-Σ1(e), Σ1(e)-Σ0(e), Σ1(e) ^ Σ0(e), Σ1(e) | Σ0(e), Σ1(e) % Σ0(e), Σ0(e) % Σ1(e), Σ1(e)/Σ0(e), Σ0(e)/Σ1(e), e-a, a-e, a ^ e, a | e, a % e, e % a, a/e, e/a,
                      T1 ^ T1Before, T1 & T1Before, T1 | T1Before, T1 - T1Before, T1Before - T1, T1 / T1Before, T1Before / T1, T1 % T1Before, T1Before % T1,
                      T2 ^ T2Before, T2 & T2Before, T2 | T2Before, T2 - T2Before, T2Before - T2, T2 / T2Before, T2Before / T2, T2 % T2Before, T2Before % T2,

                      T2 ^ T1Before, T2 & T1Before, T2 | T1Before, T2 - T1Before, T1Before - T2, T2 / T1Before, T1Before / T2, T2 % T1Before, T1Before % T2,
                      T2 ^ T1Before, T2 & T1Before, T2 | T1Before, T2 - T1Before, T1Before - T2, T2 / T1Before, T1Before / T2, T2 % T1Before, T1Before % T2,
                    );
        //PUSH(j >= 61, e, Σ0(e), Σ1(e));
        PUSH(j >= 62, Ch(e, f, g), -Ch(e, f, g), ~Ch(e, f, g));
        PUSH(j >= 63, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, K[0], K[1], K[2], K[3],
                      K[4], K[5], K[6], K[7], K[8], K[9], K[10], K[11], K[12], K[13], K[14], K[15], K[16], K[17], K[18], K[19], K[20], K[21], K[22], K[23], K[24], K[25],
                      K[26], K[27], K[28], K[29], K[30], K[31], K[32], K[33], K[34], K[35], K[36], K[37], K[38], K[39], K[40], K[41], K[42], K[43], K[44], K[45], K[46],
                      K[47], K[48], K[49], K[50], K[51], K[52], K[53], K[54], K[55], K[56], K[57], K[58], K[59], K[60], K[61], K[62], K[63]);

        T2Before = T2;
        T1Before = T1;
        
    }

    //printf("pushIdx: %u\n", pushIdx);
    return W[15];
}// python3.10 setup.py build_ext --inplace


static inline void sha256Test(const uint8_t *msg, size_t length, uint32_t* hash) {
    uint64_t bit_length = length * 8;
    uint8_t withPad[64] = {0};
    memcpy(withPad, msg, length);
    withPad[length] = 0x80;

    size_t i = length + 1;
    while ((i * 8) % 512 != 448) {
        withPad[i++] = 0;
    }

    for (int j = 7; j >= 0; j--) {
        withPad[i++] = (bit_length >> (j * 8)) & 0xFF;
    }

    uint32_t W[64];
    for (int j = 0; j < 16; j++) {
        W[j] = (withPad[j * 4] << 24) | (withPad[j * 4 + 1] << 16) | (withPad[j * 4 + 2] << 8) | (withPad[j * 4 + 3]);
    }
    for (int j = 16; j < 64; j++) {
        W[j] = σ1(W[j - 2]) + W[j - 7] + σ0(W[j - 15]) + W[j - 16];
    }

    uint32_t a = 0x6a09e667, b = 0xbb67ae85, c = 0x3c6ef372, d = 0xa54ff53a, e = 0x510e527f, f = 0x9b05688c, g = 0x1f83d9ab, h = 0x5be0cd19;

    for (int j = 0; j < 64; j++) {
        uint32_t T1 = h + Σ1(e) + Ch(e, f, g) + K[j] + W[j];
        uint32_t T2 = Σ0(a) + Maj(a, b, c);
        h = g; g = f; f = e; e = d + T1;
        d = c; c = b; b = a; a = T1 + T2;
    }
    hash[0] = a + 0x6a09e667; hash[1] = b + 0xbb67ae85; hash[2] = c + 0x3c6ef372; hash[3] = d + 0xa54ff53a;
    hash[4] = e + 0x510e527f; hash[5] = f + 0x9b05688c; hash[6] = g + 0x1f83d9ab; hash[7] = h + 0x5be0cd19;
}

void* background_loader() {

    while (1) {
        while (buffer_loaded == 1) {  
            pthread_cond_wait(&next_ready, &next_lock);
        }

        size_t initialHashOffset = ctx.hash_offset;
        for (size_t i = ctx.hash_offset; i < (initialHashOffset + USED_HASHES) && i < NUM_HASHES; i++, ctx.hash_offset++) {
         uint8_t msg_length = ctx.lengths[i];
         (ctx.secondBuffer ? ctx.secondTargetBuffer : ctx.targetBuffer)[i % USED_HASHES] =
             sha256(&ctx.data[ctx.data_offset], msg_length, i % USED_HASHES);
             ctx.data_offset += msg_length;
         }
     
         if (ctx.hash_offset >= NUM_HASHES) {
             ctx.hash_offset = 0;
             ctx.data_offset = 0;
         }

        ctx.secondBuffer = !ctx.secondBuffer;
        buffer_loaded = 1;
        pthread_cond_signal(&buffer_ready);
    }
    return NULL;
}

void nextData() {

    size_t initialHashOffset = ctx.hash_offset;
    for (size_t i = ctx.hash_offset; i < (initialHashOffset + USED_HASHES) && i < NUM_HASHES; i++, ctx.hash_offset++) {
     uint8_t msg_length = ctx.lengths[i];
     (ctx.secondBuffer ? ctx.secondTargetBuffer : ctx.targetBuffer)[i % USED_HASHES] =
         sha256(&ctx.data[ctx.data_offset], msg_length, i % USED_HASHES);
         ctx.data_offset += msg_length;
     }
 
     if (ctx.hash_offset >= NUM_HASHES) {
         ctx.hash_offset = 0;
         ctx.data_offset = 0;
     }

    /*while (buffer_loaded == 0) {  
        pthread_cond_wait(&buffer_ready, &buffer_lock);
    }

    buffer_loaded = 0;
    pthread_cond_signal(&next_ready);*/

 }

void init() {
    ctx.fd_len = open("quantum_data_async_len.bin"/*"quantumlengths.bin"*/, O_RDONLY);
    ctx.fd_data = open("quantum_data_async_data.bin"/*"quantumdata.bin"*/, O_RDONLY);
    
    fstat(ctx.fd_len, &st_len);
    fstat(ctx.fd_data, &st_data);

    ctx.lengths = mmap(NULL, st_len.st_size, PROT_READ, MAP_PRIVATE, ctx.fd_len, 0);
    ctx.data = mmap(NULL, st_data.st_size, PROT_READ, MAP_PRIVATE, ctx.fd_data, 0);

    ctx.inputBuffer = malloc(PARAM_ALLOC);
    ctx.targetBuffer = malloc(TARGET_ALLOC);

    ctx.secondInputBuffer = malloc(PARAM_ALLOC);
    ctx.secondTargetBuffer = malloc(TARGET_ALLOC);


    if (ctx.lengths == MAP_FAILED || ctx.data == MAP_FAILED || !ctx.inputBuffer || !ctx.targetBuffer)
        exit(EXIT_FAILURE);

    ctx.hash_offset = 0;
    ctx.data_offset = 0;

    //pthread_attr_t attr;
    //pthread_attr_init(&attr);
    //pthread_attr_setdetachstate(&attr, PTHREAD_CREATE_DETACHED);  

   // if (pthread_create(&loader_thread, &attr, background_loader, NULL) != 0)
     //   exit(EXIT_FAILURE);
}

void shutdown() {
    if (ctx.lengths != MAP_FAILED) { munmap(ctx.lengths, st_len.st_size); ctx.lengths = MAP_FAILED; }
    if (ctx.data != MAP_FAILED) { munmap(ctx.data, st_data.st_size); ctx.data = MAP_FAILED; }
    if (ctx.inputBuffer) free(ctx.inputBuffer);
    if (ctx.targetBuffer) free(ctx.targetBuffer);
    if (ctx.secondInputBuffer) free(ctx.secondInputBuffer);
    if (ctx.secondTargetBuffer) free(ctx.secondTargetBuffer);
    if (ctx.fd_len >= 0) { close(ctx.fd_len); ctx.fd_len = -1; }
    if (ctx.fd_data >= 0) { close(ctx.fd_data); ctx.fd_data = -1; }
}

/*void getContext(uint32_t* hex) {
    uint32_t a = hex[0] - 0x6a09e667;
    uint32_t b = hex[1] - 0xbb67ae85;
    uint32_t c = hex[2] - 0x3c6ef372;
    uint32_t d = hex[3] - 0xa54ff53a;
    uint32_t e = hex[4] - 0x510e527f;
    uint32_t f = hex[5] - 0x9b05688c;
    uint32_t g = hex[6] - 0x1f83d9ab;
    uint32_t h = hex[7] - 0x5be0cd19;

    uint32_t T263 = Σ0(b) + Maj(b,c,d);
    uint32_t T163 = a - T263;

    uint32_t T262 = Σ0(c) + Maj(c,d,e-T163);
    uint32_t T162 = b - T262;
    uint32_t a59 = f - T162;

    uint32_t T261 = Σ0(d) + Maj(d,e-T163,f-T162);
    uint32_t T161 = c - T261;
    uint32_t a58 = g - T161;

    uint32_t T260 = Σ0(e-T163) + Maj(e-T163, f-T162, g-T161);
    uint32_t T160 = d - T260;
    uint32_t a57 = h - T160;

    uint32_t T259 = Σ0(a59) + Maj(a59,a58,a57);
    uint32_t a60 = e - T163;
    uint32_t T159 = a60 - T259;

    printf("a: %u, b: %u, c: %u, d: %u, e: %u, f: %u, g: %u, h: %u, a57: %u, a58: %u, a59: %u, a60: %u\n", a,b,c,d,e,f,g,h, a57, a58, a59, a60);
    printf("T159: %u, T259: %u, T160: %u, T260: %u, T161: %u, T261: %u, T162: %u, T262: %u, T163: %u, T263: %u\n", T159, T259, T160, T260, T161, T261, T162, T262, T163, T263);


        PUSH(j >= 57, a, Σ0(a), Σ1(a));
        PUSH(j >= 58, b, Σ0(b), Σ1(b), -a, -b, ~a, ~b, a-b, a ^ b, a | b, a % b, b % a, a/b, b/a);
        PUSH(j >= 59, c, Σ0(c), Σ1(c), Maj(a, b, c), T1, T2, -T1, -T2, ~T1, ~T2, T1 - T2, T1 ^ T2, T1 & T2, T1 | T2, a ^ T2, a & T2, a | T2, a % T2, T1 ^ a,
                      T1 & a, T1 | a, T1 % a, T1 - b, T1 ^ b, T1 & b, T1 | b, T1 % b, T1/b, b/T1, T2 - b, T2 ^ b, T2 & b, T2 | b, T2 % b, T2/b, b/T2);
        PUSH(j >= 60, d, Σ0(d), Σ1(d));
        PUSH(j >= 61, e, Σ0(e), Σ1(e));
        PUSH(j >= 62, f, Σ0(f), Σ1(f), Ch(e, f, g), T262 - a, T262 ^ a, T262 & a, T262 | a, T262 % a, a % T262, T262/a, a/T262, T162 - a, T162 ^ a, T162 & a,
                      T162 | a, T162 % a, a % T162, T162/a, a/T162, T262 - T261, T262 ^ T261, T262 & T261, T262 | T261, T261 % T262, T262 % T261, T262/T261, T261/T262,
                      T162 - T161, T162 ^ T161, T162 & T161, T162 | T161, T161 % T162, T162 % T161, T162/T161, T161/T162, T262 - T161, T262 ^ T161, T262 & T161,
                      T262 | T161, T262 % T161, T161 % T262, T262/T161, T161/T262, T162 - T261, T162 ^ T261, T162 & T261, T162 | T261, T162 % T261, T261 % T162, T162/T261,  
                      T261/T162);
        PUSH(j >= 63, g, Σ0(g), Σ1(g), T2 - a, T2 ^ a, T2 & a, T2 | a, T2 % a, a % T2, T2/a, a/T2, T1 - a, T1 ^ a, T1 & a, T1 | a, T1 % a, a % T1, T1/a, a/T1, T2 - T262,
                         T2 ^ T262, T2 & T262, T2 | T262, T262 % T2, T2 % T262, T2/T262, T262/T2, T1 - T162, T1 ^ T162, T1 & T162, T1 | T162, T162 % T1, T1 % T162, T1/T162,  
                         T162/T1, T2 - T162, T2 ^ T162, T2 & T162, T2 | T162, T2 % T162, T162 % T2, T2/T162, T162/T2, T1 - T262, T1 ^ T262, T1 & T262, T1 | T262, T1 % T262,
                         T262 % T1, T1/T262, T262/T1, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, K[0], K[1], K[2], K[3],
                         K[4], K[5], K[6], K[7], K[8], K[9], K[10], K[11], K[12], K[13], K[14], K[15], K[16], K[17], K[18], K[19], K[20], K[21], K[22], K[23], K[24], K[25],
                         K[26], K[27], K[28], K[29], K[30], K[31], K[32], K[33], K[34], K[35], K[36], K[37], K[38], K[39], K[40], K[41], K[42], K[43], K[44], K[45], K[46],
                         K[47], K[48], K[49], K[50], K[51], K[52], K[53], K[54], K[55], K[56], K[57], K[58], K[59], K[60], K[61], K[62], K[63]);

    uint32_t data[] = {
        a58, Σ0(a58), Σ1(a58),

        a59, Σ0(a59), Σ1(a59),
        a58, Σ0(a58), Σ1(a58), -a59, -a58, ~a59, ~a58, a59-a58, a59 ^ a58, a59 | a58, a59 % a58, a58 % a59, a59/a58, a58/a59,

        a60, Σ0(a60), Σ1(a60),
        a59, Σ0(a59), Σ1(a59), -a60, -a59, ~a60, ~a59, a60-a59, a60 ^ a59, a60 | a59, a60 % a59, a59 % a60, a60/a59, a59/a60,
        a58, Σ0(a58), Σ1(a58), Maj(a60, a59, a58), T159, T259, -T159, -T259, ~T159, ~T259, T159 - T259, T159 ^ T259, T159 & T259, T159 | T259, a60 ^ T259, a60 & T259, a60 | T259, a60 % T259, T159 ^ a60,
                      T159 & a60, T159 | a60, T159 % a60, T159 - a59, T159 ^ a59, T159 & a59, T159 | a59, T159 % a59, T159/a59, a59/T159, T259 - a59, T259 ^ a59, T259 & a59, T259 | a59, T259 % a59, T259/a59, a59/T259,

        d, Σ0(d), Σ1(d),
        a60, Σ0(a60), Σ1(a60), -d, -a60, ~d, ~a60, d-a60, d ^ a60, d | a60, d % a60, a60 % d, d/a60, a60/d,
        a59, Σ0(a59), Σ1(a59), Maj(d, a60, a59), T160, T260, -T160, -T260, ~T160, ~T260, T160 - T260, T160 ^ T260, T160 & T260, T160 | T260, d ^ T260, d & T260, d | T260, d % T260, T160 ^ d,
                      T160 & d, T160 | d, T160 % d, T160 - a60, T160 ^ a60, T160 & a60, T160 | a60, T160 % a60, T160/a60, a60/T160, T260 - a60, T260 ^ a60, T260 & a60, T260 | a60, T260 % a60, T260/a60, a60/T260,
        a58, Σ0(a58), Σ1(a58),

        c, Σ0(c), Σ1(c),
        d, Σ0(d), Σ1(d), -c, -d, ~c, ~d, c-d, c ^ d, c | d, c % d, d % c, c/d, d/c,
        a60, Σ0(a60), Σ1(a60), Maj(c, d, a60), T161, T261, -T161, -T261, ~T161, ~T261, T161 - T261, T161 ^ T261, T161 & T261, T161 | T261, c ^ T261, c & T261, c | T261, c % T261, T161 ^ c,
                      T161 & c, T161 | c, T161 % c, T161 - d, T161 ^ d, T161 & d, T161 | d, T161 % d, T161/d, d/T161, T261 - d, T261 ^ d, T261 & d, T261 | d, T261 % d, T261/d, d/T261,
        a59, Σ0(a59), Σ1(a59),
        a58+T161, Σ0(a58+T161), Σ1(a58+T161),

        b, Σ0(b), Σ1(b),
        c, Σ0(c), Σ1(c), -b, -c, ~b, ~c, b-c, b ^ c, b | c, b % c, c % b, b/c, c/b,
        d, Σ0(d), Σ1(d), Maj(b, c, d), T162, T262, -T162, -T262, ~T162, ~T262, T162 - T262, T162 ^ T262, T162 & T262, T162 | T262, b ^ T262, b & T262, b | T262, b % T262, T162 ^ b,
                      T162 & b, T162 | b, T162 % b, T162 - c, T162 ^ c, T162 & c, T162 | c, T162 % c, T162/c, c/T162, T262 - c, T262 ^ c, T262 & c, T262 | c, T262 % c, T262/c, c/T262,
        a60, Σ0(a60), Σ1(a60),
        a59+T162, Σ0(a59+T162), Σ1(a59+T162),
        a58+T161, Σ0(a58+T161), Σ1(a58+T161), Ch(a59+T262, a58+T161, h), T262 - b, T262 ^ b, T262 & b, T262 | b, T262 % b, b % T262, T262/b, b/T262, T162 - b, T162 ^ b, T162 & b,
                      T162 | b, T162 % b, b % T162, T162/b, b/T162, T262 - T261, T262 ^ T261, T262 & T261, T262 | T261, T261 % T262, T262 % T261, T262/T261, T261/T262,
                      T162 - T161, T162 ^ T161, T162 & T161, T162 | T161, T161 % T162, T162 % T161, T162/T161, T161/T162, T262 - T161, T262 ^ T161, T262 & T161,
                      T262 | T161, T262 % T161, T161 % T262, T262/T161, T161/T262, T162 - T261, T162 ^ T261, T162 & T261, T162 | T261, T162 % T261, T261 % T162, T162/T261,  
                      T261/T162,
        
        a, Σ0(a), Σ1(a),
        b, Σ0(b), Σ1(b), -a, -b, ~a, ~b, a-b, a ^ b, a | b, a % b, b % a, a/b, b/a,
        c, Σ0(c), Σ1(c), Maj(a, b, c), T163, T263, -T163, -T263, ~T163, ~T263, T163 - T263, T163 ^ T263, T163 & T263, T163 | T263, a ^ T263, a & T263, a | T263, a % T263, T163 ^ a,
                      T163 & a, T163 | a, T163 % a, T163 - b, T163 ^ b, T163 & b, T163 | b, T163 % b, T163/b, b/T163, T263 - b, T263 ^ b, T263 & b, T263 | b, T263 % b, T263/b, b/T263,
        d, Σ0(d), Σ1(d),
        a60+T163, Σ0(a60+T163), Σ1(a60+T163),
        a59+T162, Σ0(a59+T162), Σ1(a59+T162), Ch(a60+T163, a59+T162, a58+T161), T263 - a, T263 ^ a, T263 & a, T263 | a, T263 % a, a % T263, T263/a, a/T263, T163 - a, T163 ^ a, T163 & a,
                      T163 | a, T163 % a, a % T163, T163/a, a/T163, T263 - T262, T263 ^ T262, T263 & T262, T263 | T262, T262 % T263, T263 % T262, T263/T262, T262/T263,
                      T163 - T162, T163 ^ T162, T163 & T162, T163 | T162, T162 % T163, T163 % T162, T163/T162, T162/T163, T263 - T162, T263 ^ T162, T263 & T162,
                      T263 | T162, T263 % T162, T162 % T263, T263/T162, T162/T263, T163 - T262, T163 ^ T262, T163 & T262, T163 | T262, T163 % T262, T262 % T163, T163/T262,  
                      T262/T162,
        g, Σ0(g), Σ1(g), T2 - a, T2 ^ a, T2 & a, T2 | a, T2 % a, a % T2, T2/a, a/T2, T1 - a, T1 ^ a, T1 & a, T1 | a, T1 % a, a % T1, T1/a, a/T1, T2 - T262,
                         T2 ^ T262, T2 & T262, T2 | T262, T262 % T2, T2 % T262, T2/T262, T262/T2, T1 - T162, T1 ^ T162, T1 & T162, T1 | T162, T162 % T1, T1 % T162, T1/T162,  
                         T162/T1, T2 - T162, T2 ^ T162, T2 & T162, T2 | T162, T2 % T162, T162 % T2, T2/T162, T162/T2, T1 - T262, T1 ^ T262, T1 & T262, T1 | T262, T1 % T262,
                         T262 % T1, T1/T262, T262/T1, 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, K[0], K[1], K[2], K[3],
                         K[4], K[5], K[6], K[7], K[8], K[9], K[10], K[11], K[12], K[13], K[14], K[15], K[16], K[17], K[18], K[19], K[20], K[21], K[22], K[23], K[24], K[25],
                         K[26], K[27], K[28], K[29], K[30], K[31], K[32], K[33], K[34], K[35], K[36], K[37], K[38], K[39], K[40], K[41], K[42], K[43], K[44], K[45], K[46],
                         K[47], K[48], K[49], K[50], K[51], K[52], K[53], K[54], K[55], K[56], K[57], K[58], K[59], K[60], K[61], K[62], K[63]
    };
}

int main() {

    uint32_t hash[8] = {0};

    //sha256Test("Hello", strlen("Hello"), hash);

    sha256("Hello", strlen("Hello"), 0);

    //getContext(hash);

    for(uint32_t i = 0; i < 8; i++)
        printf("%x", hash[i]);
}*/


/*static inline void GetWs(uint16_t sh, uint32_t *W) {
    uint32_t length = 2;

    uint64_t bit_length = length * 8;
    uint8_t withPad[64] = {0};

    withPad[0] = sh;

    withPad[length] = 0x80;

    size_t i = length + 1;
    while ((i * 8) % 512 != 448) {
        withPad[i++] = 0;
    }

    for (int j = 7; j >= 0; j--) {
        withPad[i++] = (bit_length >> (j * 8)) & 0xFF;
    }

    for (int j = 0; j < 16; j++) {
        W[j] = (withPad[j * 4] << 24) | (withPad[j * 4 + 1] << 16) | (withPad[j * 4 + 2] << 8) | (withPad[j * 4 + 3]);
    }
    for (int j = 16; j < 64; j++) {
        W[j] = σ1(W[j - 2]) + W[j - 7] + σ0(W[j - 15]) + W[j - 16];
    }
}

int main() {
uint32_t W[64] = {0};
uint32_t W2[64] = {0};
GetWs(0x4836, W);
GetWs(0xfe11, W2);

for (size_t i = 0; i < 64; i++)
{
    if(W[i] == W2[i])
    {
        printf("CONST W[%zu]: %u\n", i, W[i]);
    }
}

}*/
