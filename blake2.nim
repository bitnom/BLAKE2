## 
##    BLAKE2 reference source code package - optimized Nim implementations
## 
##    Wrapped in 2017 by Tom Ashley <www.TomAshley.me>
## 
##    To the extent possible under law, the author(s) have dedicated all copyright
##    and related and neighboring rights to this software to the public domain
##    worldwide. This software is distributed without any warranty.
##    <http://creativecommons.org/publicdomain/zero/1.0/>
## 
##    https://github.com/TomAshley303/BLAKE2
## 

when defined(_WIN32) or defined(__CYGWIN__):
  const
    BLAKE2_DLL_IMPORT* = __declspec(dllimport)
    BLAKE2_DLL_EXPORT* = __declspec(dllexport)
    BLAKE2_DLL_PRIVATE* = true
elif __GNUC__ >= 4:
  const
    BLAKE2_DLL_IMPORT* = __attribute__((visibility("default")))
    BLAKE2_DLL_EXPORT* = __attribute__((visibility("default")))
    BLAKE2_DLL_PRIVATE* = __attribute__((visibility("hidden")))
else:
  const
    BLAKE2_DLL_IMPORT* = true
    BLAKE2_DLL_EXPORT* = true
    BLAKE2_DLL_PRIVATE* = true
when defined(BLAKE2_DLL):
  when defined(BLAKE2_DLL_EXPORTS): ##  defined if we are building the DLL
    const
      BLAKE2_API* = BLAKE2_DLL_EXPORT
  else:
    const
      BLAKE2_API* = BLAKE2_DLL_IMPORT
  const
    BLAKE2_PRIVATE* = BLAKE2_DLL_PRIVATE
else:
  const
    BLAKE2_API* = true
    BLAKE2_PRIVATE* = true
type
  blake2s_constant* = enum
    BLAKE2S_SALTBYTES = 8, BLAKE2S_OUTBYTES = 32, BLAKE2S_BLOCKBYTES = 64

const
  BLAKE2S_PERSONALBYTES = BLAKE2S_SALTBYTES
  BLAKE2S_KEYBYTES = BLAKE2S_OUTBYTES

type
  blake2b_constant* = enum
    BLAKE2B_SALTBYTES = 16, BLAKE2B_OUTBYTES = 64, BLAKE2B_BLOCKBYTES = 128

const
  BLAKE2B_PERSONALBYTES = BLAKE2B_SALTBYTES
  BLAKE2B_KEYBYTES = BLAKE2B_OUTBYTES

type
  blake2s_param* = object
    digest_length*: uint8_t    ##  1
    key_length*: uint8_t       ##  2
    fanout*: uint8_t           ##  3
    depth*: uint8_t            ##  4
    leaf_length*: uint32_t     ##  8
    node_offset*: array[6, uint8_t] ##  14
    node_depth*: uint8_t       ##  15
    inner_length*: uint8_t     ##  16
                         ##  uint8_t  reserved[0];
    salt*: array[BLAKE2S_SALTBYTES, uint8_t] ##  24
    personal*: array[BLAKE2S_PERSONALBYTES, uint8_t] ##  32
  
  blake2s_state* = object
    h*: array[8, uint32_t]
    t*: array[2, uint32_t]
    f*: array[2, uint32_t]
    buf*: array[2 * BLAKE2S_BLOCKBYTES, uint8_t]
    buflen*: uint32_t
    outlen*: uint8_t
    last_node*: uint8_t

  blake2b_param* = object
    digest_length*: uint8_t    ##  1
    key_length*: uint8_t       ##  2
    fanout*: uint8_t           ##  3
    depth*: uint8_t            ##  4
    leaf_length*: uint32_t     ##  8
    node_offset*: uint64_t     ##  16
    node_depth*: uint8_t       ##  17
    inner_length*: uint8_t     ##  18
    reserved*: array[14, uint8_t] ##  32
    salt*: array[BLAKE2B_SALTBYTES, uint8_t] ##  48
    personal*: array[BLAKE2B_PERSONALBYTES, uint8_t] ##  64
  
  blake2b_state* = object
    h*: array[8, uint64_t]
    t*: array[2, uint64_t]
    f*: array[2, uint64_t]
    buf*: array[2 * BLAKE2B_BLOCKBYTES, uint8_t]
    buflen*: uint32_t
    outlen*: uint8_t
    last_node*: uint8_t

  blake2sp_state* = object
    S*: array[8, array[1, blake2s_state]]
    R*: array[1, blake2s_state]
    buf*: array[8 * BLAKE2S_BLOCKBYTES, uint8_t]
    buflen*: uint32_t
    outlen*: uint8_t

  blake2bp_state* = object
    S*: array[4, array[1, blake2b_state]]
    R*: array[1, blake2b_state]
    buf*: array[4 * BLAKE2B_BLOCKBYTES, uint8_t]
    buflen*: uint32_t
    outlen*: uint8_t


##  Streaming API

proc blake2s_init*(S: ptr blake2s_state; outlen: csize): cint
proc blake2s_init_key*(S: ptr blake2s_state; outlen: csize; key: pointer; keylen: csize): cint
proc blake2s_init_param*(S: ptr blake2s_state; P: ptr blake2s_param): cint
proc blake2s_update*(S: ptr blake2s_state; `in`: ptr uint8_t; inlen: csize): cint
proc blake2s_final*(S: ptr blake2s_state; `out`: ptr uint8_t; outlen: csize): cint
proc blake2b_init*(S: ptr blake2b_state; outlen: csize): cint
proc blake2b_init_key*(S: ptr blake2b_state; outlen: csize; key: pointer; keylen: csize): cint
proc blake2b_init_param*(S: ptr blake2b_state; P: ptr blake2b_param): cint
proc blake2b_update*(S: ptr blake2b_state; `in`: ptr uint8_t; inlen: csize): cint
proc blake2b_final*(S: ptr blake2b_state; `out`: ptr uint8_t; outlen: csize): cint
proc blake2sp_init*(S: ptr blake2sp_state; outlen: csize): cint
proc blake2sp_init_key*(S: ptr blake2sp_state; outlen: csize; key: pointer;
                       keylen: csize): cint
proc blake2sp_update*(S: ptr blake2sp_state; `in`: ptr uint8_t; inlen: csize): cint
proc blake2sp_final*(S: ptr blake2sp_state; `out`: ptr uint8_t; outlen: csize): cint
proc blake2bp_init*(S: ptr blake2bp_state; outlen: csize): cint
proc blake2bp_init_key*(S: ptr blake2bp_state; outlen: csize; key: pointer;
                       keylen: csize): cint
proc blake2bp_update*(S: ptr blake2bp_state; `in`: ptr uint8_t; inlen: csize): cint
proc blake2bp_final*(S: ptr blake2bp_state; `out`: ptr uint8_t; outlen: csize): cint
##  Simple API

proc blake2s*(`out`: ptr uint8_t; `in`: pointer; key: pointer; outlen: csize;
             inlen: csize; keylen: csize): cint
proc blake2b*(`out`: ptr uint8_t; `in`: pointer; key: pointer; outlen: csize;
             inlen: csize; keylen: csize): cint
proc blake2sp*(`out`: ptr uint8_t; `in`: pointer; key: pointer; outlen: csize;
              inlen: csize; keylen: csize): cint
proc blake2bp*(`out`: ptr uint8_t; `in`: pointer; key: pointer; outlen: csize;
              inlen: csize; keylen: csize): cint
proc blake2*(`out`: ptr uint8_t; `in`: pointer; key: pointer; outlen: csize; inlen: csize;
            keylen: csize): cint {.inline.} =
  return blake2b(`out`, `in`, key, outlen, inlen, keylen)
