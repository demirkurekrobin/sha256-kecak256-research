# distutils: language = c
# cython: boundscheck=False, wraparound=False, initializedcheck=False

import numpy as np
cimport numpy as np
from libc.string cimport memcpy
from libc.stdint cimport uint32_t, uint8_t, int32_t
from libc.stdlib cimport malloc, free

cdef extern from "sha256_buffer.h":
    struct ctx_type:
        int fd_len, fd_data;
        uint8_t *lengths;
        uint8_t *data;
        uint32_t *inputBuffer, *targetBuffer;
        uint32_t *secondInputBuffer, *secondTargetBuffer;
        size_t hash_offset, data_offset;
        uint32_t secondBuffer;
    cdef ctx_type ctx

    void init()
    void nextData()
    void shutdown()

cdef int NUM_HASHES = 300000000
cdef int USED_HASHES = NUM_HASHES // 300
cdef int PARAM_COUNT = 692
cdef int PARAM_ALLOC = PARAM_COUNT * USED_HASHES * 4  # sizeof(uint32_t)
cdef int TARGET_ALLOC = USED_HASHES * 4  # sizeof(uint32_t)

def call_init():
    init()

def call_nextData():
    nextData()

    cdef np.npy_intp dims_input[2]
    dims_input[0] = USED_HASHES
    dims_input[1] = PARAM_COUNT

    cdef np.npy_intp dims_target[1]
    dims_target[0] = USED_HASHES

    cdef uint32_t* input_buffer = ctx.inputBuffer if ctx.secondBuffer == 0 else ctx.secondInputBuffer
    cdef uint32_t* target_buffer = ctx.targetBuffer if ctx.secondBuffer == 0 else ctx.secondTargetBuffer

    cdef np.ndarray[np.uint32_t, ndim=2] arr_input = np.PyArray_SimpleNewFromData(
        2, dims_input, np.NPY_UINT32, <void*>input_buffer
    )
    cdef np.ndarray[np.uint32_t, ndim=1] arr_target = np.PyArray_SimpleNewFromData(
        1, dims_target, np.NPY_UINT32, <void*>target_buffer
    )

    np.PyArray_SetBaseObject(arr_input, None)
    np.PyArray_SetBaseObject(arr_target, None)

    indices = np.arange(USED_HASHES, dtype=np.int32)
    np.random.shuffle(indices)

    return arr_input[indices], arr_target[indices]

def call_shutdown():
    shutdown()
