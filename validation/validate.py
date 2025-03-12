import struct
import hashlib
import array
import tensorflow as tf
import numpy as np
import random
from tqdm import tqdm

MODEL_PATH = "pre-trained-sha256_model.keras"
PARAM_COUNT = 693
SAMPLES_PER_CLASS = 100
MAX_LENGTH = 55 

def rotr(x, n):
    return ((x >> n) | (x << (32 - n))) & 0xFFFFFFFF

def big_sigma0(x):
    return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22)

def big_sigma1(x):
    return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25)

def small_sigma0(x):
    return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3)

def small_sigma1(x):
    return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10)

def ch(x, y, z):
    return (x & y) ^ (~x & z)

def maj(x, y, z):
    return (x & y) ^ (x & z) ^ (y & z)

K = [
    0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
    0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
    0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
    0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7, 0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
    0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
    0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
    0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
    0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
]

inputs = array.array('I', []) # This buffer is used as a copy of the internal state of the sha-256 message handler to verify the correct reconstruction
extractedInputs = array.array('I', []) # The extracted internal state of the last 7 rounds of the sha-256 message handler. It only uses the output hash to calculate that.

def param_write(outArr, j, a, b=0, c=0, e=0, f=0, g=0, T1=0, T2=0, T1Before=0, T2Before=0):
    if j >= 56:
            outArr.extend([big_sigma0(a), big_sigma1(a), (-a) & 0xFFFFFFFF, (~a) & 0xFFFFFFFF, (-big_sigma0(a)) & 0xFFFFFFFF, (~big_sigma0(a)) & 0xFFFFFFFF, (-big_sigma1(a)) & 0xFFFFFFFF, (~big_sigma1(a)) & 0xFFFFFFFF,
                    (big_sigma0(a)-big_sigma1(a)) & 0xFFFFFFFF, (big_sigma1(a)-big_sigma0(a)) & 0xFFFFFFFF, (big_sigma1(a) ^ big_sigma0(a)) & 0xFFFFFFFF, (big_sigma1(a) | big_sigma0(a)) & 0xFFFFFFFF, (big_sigma1(a) % big_sigma0(a)) & 0xFFFFFFFF, (big_sigma0(a) % big_sigma1(a)) & 0xFFFFFFFF, (big_sigma1(a)//big_sigma0(a)) & 0xFFFFFFFF, (big_sigma0(a)//big_sigma1(a)) & 0xFFFFFFFF])
    if j >= 57:
        outArr.extend([(a-b) & 0xFFFFFFFF, (b-a) & 0xFFFFFFFF, (a ^ b) & 0xFFFFFFFF, (a | b) & 0xFFFFFFFF, (a % b) & 0xFFFFFFFF, (b % a) & 0xFFFFFFFF, (a//b) & 0xFFFFFFFF, (b//a) & 0xFFFFFFFF])
    if j >= 58:
        outArr.extend([maj(a, b, c), (-maj(a, b, c)) & 0xFFFFFFFF, (~maj(a, b, c)) & 0xFFFFFFFF])
    if j >= 59:
        outArr.extend([T1, T2, (-T1) & 0xFFFFFFFF, (-T2) & 0xFFFFFFFF, (~T1) & 0xFFFFFFFF, (~T2) & 0xFFFFFFFF, (T1 - T2) & 0xFFFFFFFF, (T1 ^ T2) & 0xFFFFFFFF, (T1 & T2) & 0xFFFFFFFF, (T1 | T2) & 0xFFFFFFFF, (a ^ T2) & 0xFFFFFFFF, (a & T2) & 0xFFFFFFFF, (a | T2) & 0xFFFFFFFF, (a % T2) & 0xFFFFFFFF, (T1 ^ a) & 0xFFFFFFFF,
                      (T1 & a) & 0xFFFFFFFF, (T1 | a) & 0xFFFFFFFF, (T1 % a) & 0xFFFFFFFF, (T1 - b) & 0xFFFFFFFF, (T1 ^ b) & 0xFFFFFFFF, (T1 & b) & 0xFFFFFFFF, (T1 | b) & 0xFFFFFFFF, (T1 % b) & 0xFFFFFFFF, (T1//b) & 0xFFFFFFFF, (b//T1) & 0xFFFFFFFF, (T2 - b) & 0xFFFFFFFF, (T2 ^ b) & 0xFFFFFFFF, (T2 & b) & 0xFFFFFFFF, (T2 | b) & 0xFFFFFFFF, (T2 % b) & 0xFFFFFFFF, (T2//b) & 0xFFFFFFFF, (b//T2) & 0xFFFFFFFF])
    if j >= 60:
        outArr.extend([e, big_sigma0(e), big_sigma1(e), (-e) & 0xFFFFFFFF, (~e) & 0xFFFFFFFF, (-big_sigma0(e)) & 0xFFFFFFFF, (~big_sigma0(e)) & 0xFFFFFFFF, (-big_sigma1(e)) & 0xFFFFFFFF, (~big_sigma1(e)) & 0xFFFFFFFF, 
            (big_sigma0(e)-big_sigma1(e)) & 0xFFFFFFFF, (big_sigma1(e)-big_sigma0(e)) & 0xFFFFFFFF, (big_sigma1(e) ^ big_sigma0(e)) & 0xFFFFFFFF, (big_sigma1(e) | big_sigma0(e)) & 0xFFFFFFFF, (big_sigma1(e) % big_sigma0(e)) & 0xFFFFFFFF, (big_sigma0(e) % big_sigma1(e)) & 0xFFFFFFFF, (big_sigma1(e)//big_sigma0(e)) & 0xFFFFFFFF, (big_sigma0(e)//big_sigma1(e)) & 0xFFFFFFFF, (e-a) & 0xFFFFFFFF, (a-e) & 0xFFFFFFFF, (a ^ e) & 0xFFFFFFFF, (a | e) & 0xFFFFFFFF, (a % e) & 0xFFFFFFFF, (e % a) & 0xFFFFFFFF, (a//e) & 0xFFFFFFFF, (e//a) & 0xFFFFFFFF,
            (T1 ^ T1Before) & 0xFFFFFFFF, (T1 & T1Before) & 0xFFFFFFFF, (T1 | T1Before) & 0xFFFFFFFF, (T1 - T1Before) & 0xFFFFFFFF, (T1Before - T1) & 0xFFFFFFFF, (T1 // T1Before) & 0xFFFFFFFF, (T1Before // T1) & 0xFFFFFFFF, (T1 % T1Before) & 0xFFFFFFFF, (T1Before % T1) & 0xFFFFFFFF,
            (T2 ^ T2Before) & 0xFFFFFFFF, (T2 & T2Before) & 0xFFFFFFFF, (T2 | T2Before) & 0xFFFFFFFF, (T2 - T2Before) & 0xFFFFFFFF, (T2Before - T2) & 0xFFFFFFFF, (T2 // T2Before) & 0xFFFFFFFF, (T2Before // T2) & 0xFFFFFFFF, (T2 % T2Before) & 0xFFFFFFFF, (T2Before % T2) & 0xFFFFFFFF,

            (T2 ^ T1Before) & 0xFFFFFFFF, (T2 & T1Before) & 0xFFFFFFFF, (T2 | T1Before) & 0xFFFFFFFF, (T2 - T1Before) & 0xFFFFFFFF, (T1Before - T2) & 0xFFFFFFFF, (T2 // T1Before) & 0xFFFFFFFF, (T1Before // T2) & 0xFFFFFFFF, (T2 % T1Before) & 0xFFFFFFFF, (T1Before % T2) & 0xFFFFFFFF,
            (T2 ^ T1Before) & 0xFFFFFFFF, (T2 & T1Before) & 0xFFFFFFFF, (T2 | T1Before) & 0xFFFFFFFF, (T2 - T1Before) & 0xFFFFFFFF, (T1Before - T2) & 0xFFFFFFFF, (T2 // T1Before) & 0xFFFFFFFF, (T1Before // T2) & 0xFFFFFFFF, (T2 % T1Before) & 0xFFFFFFFF, (T1Before % T2) & 0xFFFFFFFF])
    if j >= 61:
        outArr.extend([e, big_sigma0(e), big_sigma1(e)])
    if j >= 62:
        outArr.extend([ch(e, f, g), (-ch(e, f, g)) & 0xFFFFFFFF, (~ch(e, f, g)) & 0xFFFFFFFF])
    if j >= 63:
        outArr.extend([0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19, K[0], K[1], K[2], K[3],
                K[4], K[5], K[6], K[7], K[8], K[9], K[10], K[11], K[12], K[13], K[14], K[15], K[16], K[17], K[18], K[19], K[20], K[21], K[22], K[23], K[24], K[25],
                K[26], K[27], K[28], K[29], K[30], K[31], K[32], K[33], K[34], K[35], K[36], K[37], K[38], K[39], K[40], K[41], K[42], K[43], K[44], K[45], K[46],
                K[47], K[48], K[49], K[50], K[51], K[52], K[53], K[54], K[55], K[56], K[57], K[58], K[59], K[60], K[61], K[62], K[63]])


def sha256_dev(msg: bytes):
    """
    This function is an original SHA-256 implementation that supports all inputs from 1-55 bytes
    and performs the same calculations as the real SHA-256 function. Below, the hash is checked 
    to ensure it is the same as the one from the Python built-in function.
    """
    length = len(msg)
    bit_length = length * 8
    with_pad = bytearray(64)
    with_pad[:length] = msg
    with_pad[length] = 0x80
    
    i = length + 1
    while (i * 8) % 512 != 448:
        with_pad[i] = 0
        i += 1
    
    with_pad[i:i+8] = bit_length.to_bytes(8, 'big')
    
    W = [0] * 64
    for j in range(16):
        W[j] = struct.unpack('>I', with_pad[j*4:j*4+4])[0]
    
    for j in range(16, 64):
        W[j] = (small_sigma1(W[j - 2]) + W[j - 7] + small_sigma0(W[j - 15]) + W[j - 16]) & 0xFFFFFFFF
    
    a, b, c, d, e, f, g, h = 0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a, 0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19
    
    T1Before, T2Before = 0, 0
    for j in range(64):
        T1 = (h + big_sigma1(e) + ch(e, f, g) + K[j] + W[j]) & 0xFFFFFFFF
        T2 = (big_sigma0(a) + maj(a, b, c)) & 0xFFFFFFFF
        h = g
        g = f
        f = e
        e = (d + T1) & 0xFFFFFFFF
        d = c
        c = b
        b = a
        a = (T1 + T2) & 0xFFFFFFFF

        param_write(inputs, j, a, b, c, e, f, g, T1, T2, T1Before, T2Before)

        T1Before, T2Before = T1, T2
    
    hash_values = [
        (a + 0x6a09e667) & 0xFFFFFFFF,
        (b + 0xbb67ae85) & 0xFFFFFFFF,
        (c + 0x3c6ef372) & 0xFFFFFFFF,
        (d + 0xa54ff53a) & 0xFFFFFFFF,
        (e + 0x510e527f) & 0xFFFFFFFF,
        (f + 0x9b05688c) & 0xFFFFFFFF,
        (g + 0x1f83d9ab) & 0xFFFFFFFF,
        (h + 0x5be0cd19) & 0xFFFFFFFF
    ]
    return ''.join(f'{x:08x}' for x in hash_values)

def get_context(my_hash):
    """
    This function is able to reconstruct the internal state of the last rounds of the sha-256 message handler function 
    and does so completely without prior knowledge only from the hash, it is checked below whether the values are actually correct 
    and match the actual internal values from our hash function.
    """
    hash_values = [int(my_hash[i:i+8], 16) for i in range(0, 64, 8)]
    a = (hash_values[0] - 0x6a09e667) & 0xFFFFFFFF
    b = (hash_values[1] - 0xbb67ae85) & 0xFFFFFFFF
    c = (hash_values[2] - 0x3c6ef372) & 0xFFFFFFFF
    d = (hash_values[3] - 0xa54ff53a) & 0xFFFFFFFF
    e = (hash_values[4] - 0x510e527f) & 0xFFFFFFFF
    f = (hash_values[5] - 0x9b05688c) & 0xFFFFFFFF
    g = (hash_values[6] - 0x1f83d9ab) & 0xFFFFFFFF
    h = (hash_values[7] - 0x5be0cd19) & 0xFFFFFFFF

    T263 = (big_sigma0(b) + maj(b, c, d)) & 0xFFFFFFFF
    T163 = (a - T263) & 0xFFFFFFFF

    T262 = (big_sigma0(c) + maj(c, d, (e - T163) & 0xFFFFFFFF)) & 0xFFFFFFFF
    T162 = (b - T262) & 0xFFFFFFFF
    a58 = (f - T162) & 0xFFFFFFFF

    T261 = (big_sigma0(d) + maj(d, (e - T163) & 0xFFFFFFFF, (f - T162) & 0xFFFFFFFF)) & 0xFFFFFFFF
    T161 = (c - T261) & 0xFFFFFFFF
    a57 = (g - T161) & 0xFFFFFFFF

    T260 = (big_sigma0((e - T163) & 0xFFFFFFFF) + maj((e - T163) & 0xFFFFFFFF, (f - T162) & 0xFFFFFFFF, (g - T161) & 0xFFFFFFFF)) & 0xFFFFFFFF
    T160 = (d - T260) & 0xFFFFFFFF
    a56 = (h - T160) & 0xFFFFFFFF

    T259 = (big_sigma0(a58) + maj(a58, a57, a56)) & 0xFFFFFFFF
    a59 = (e - T163) & 0xFFFFFFFF
    T159 = (a59 - T259) & 0xFFFFFFFF

    param_write(extractedInputs, 56, a56)
    param_write(extractedInputs, 57, a57, a56)
    param_write(extractedInputs, 58, a58, a57, a56)
    param_write(extractedInputs, 59, a59, a58, a57, T1=T159, T2=T259)
    param_write(extractedInputs, 60, d, a59, a58, h, T1=T160, T2=T260, T1Before=T159, T2Before=T259)
    param_write(extractedInputs, 61, c, d, a59, g, h, T1=T161, T2=T261, T1Before=T160, T2Before=T260)
    param_write(extractedInputs, 62, b, c, d, f, g, h, T1=T162, T2=T262, T1Before=T161, T2Before=T261)
    param_write(extractedInputs, 63, a, b, c, e, f, g, T1=T163, T2=T263, T1Before=T162, T2Before=T262)

model = tf.keras.models.load_model(MODEL_PATH)
print("✅ Model successfully loaded!")

correct_predictions = 0
total_predictions = 0
progress_bar = tqdm(total=MAX_LENGTH * SAMPLES_PER_CLASS, desc="🔄 Testing model")

for length in range(1, MAX_LENGTH + 1):
    for _ in range(SAMPLES_PER_CLASS):
        random_bytes = bytes(random.randint(0, 255) for _ in range(length))
        my_hash = sha256_dev(random_bytes)

        official_hash = hashlib.sha256(random_bytes).hexdigest()
        get_context(my_hash)

        if my_hash != official_hash:
            print("❌ Error: Hash calculations differ!")
            exit(-1)

        if inputs != extractedInputs:
            print("❌ Error: Hash internal state could not be restored correctly!")
            exit(-1)
        
        input_data = np.array(extractedInputs, dtype=np.uint32).reshape(1, PARAM_COUNT)
        predicted_class = np.argmax(model.predict(input_data, verbose=0))
        true_class = length - 1
        extractedInputs = array.array('I', [])
        inputs = array.array('I', [])

        if predicted_class == true_class:
            correct_predictions += 1
        total_predictions += 1
        progress_bar.update(1)

progress_bar.close()

print(f"✅ Correct hash calculation validated!")
print(f"✅ Correct recovery of the hash internal state validated!")

accuracy = (correct_predictions / total_predictions) * 100
baseline_accuracy = (1 / 55) * 100
improvement_factor = accuracy / baseline_accuracy

print(f"🎯 Model accuracy over {total_predictions} tests: {accuracy:.2f}%")
print(f"📊 Expected random accuracy: {baseline_accuracy:.2f}%")
print(f"🚀 Model is {improvement_factor:.2f}x more accurate than random guessing!")
