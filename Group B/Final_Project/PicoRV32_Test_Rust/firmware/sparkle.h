/* SPDX-License-Identifier: CC0-1.0
 * Minimal SPARKLE-256 + Schwaemm-128-128 (encrypt/decrypt)
 * Based on the SPARKLE suite specification (v1.2, 2021-05-17).
 *
 * Build:  cc -O3 -std=c99 sparkle_schwaemm128.c -o schwaemm128
 *
 * Notes:
 * - Little-endian byte order as per spec.
 * - SPARKLE-256 slim/big use 7 and 10 steps respectively.
 * - Schwaemm-128-128: n=256, r=128, c=128, tag=128.
 */

#pragma once

#include <stdint.h>
#include <string.h>

#define R_BYTES 16u
#define C_BYTES 16u
#define TAG_BYTES 16u

/* ---- endian helpers ---- */
static inline uint32_t load32le(const void *p){ const uint8_t *b=(const uint8_t*)p;
  return (uint32_t)b[0]|((uint32_t)b[1]<<8)|((uint32_t)b[2]<<16)|((uint32_t)b[3]<<24); }
static inline void store32le(void *p, uint32_t v){ uint8_t *b=(uint8_t*)p;
  b[0]=(uint8_t)v; b[1]=(uint8_t)(v>>8); b[2]=(uint8_t)(v>>16); b[3]=(uint8_t)(v>>24); }

static inline uint32_t rotl32(uint32_t x, unsigned r) { r &= 31u; return r ? (x << r) | (x >> (32u - r)) : x; }
static inline uint32_t rotr32(uint32_t x, unsigned r) { r &= 31u; return r ? (x >> r) | (x << (32u - r)) : x; }

/* ---- Alzette A_c (Algorithm 2.4) ---- */
static inline void alzette(uint32_t *x, uint32_t *y, uint32_t c){
  *x = *x + rotr32(*y,31);
  *y ^= rotr32(*x,24);
  *x ^= c;

  *x = *x + rotr32(*y,17);
  *y ^= rotr32(*x,17);
  *x ^= c;

  *x = *x + rotr32(*y, 0);
  *y ^= rotr32(*x,31);
  *x ^= c;

  *x = *x + rotr32(*y,24);
  *y ^= rotr32(*x,16);
  *x ^= c;
}

/* ---- SPARKLE-256 step constants (Algorithm 2.1) ---- */
static const uint32_t Cc[8] = {
  0xB7E15162u, 0xBF715880u,
  0x38B4DA56u, 0x324E7738u,
  0xBB1185EBu, 0x4F7C7B57u,
  0xCFBFA1C8u, 0xC2B3293Du
};

/* State layout: state[0..7] = x0,y0,x1,y1,x2,y2,x3,y3 (8 x 32-bit = 256-bit) */

/* ---- L_4 diffusion (nb=4, hb=2) (Alg. 2.5 + Def. 2.1.2) ----
 * Feistel with M_hb mixing from left half (branches 0,1) into right half (2,3),
 * then rotate right-half branches left by 1, then swap halves.
 */
static inline void L4(uint32_t s[8]){
  uint32_t x0=s[0], y0=s[1], x1=s[2], y1=s[3], x2=s[4], y2=s[5], x3=s[6], y3=s[7];

  uint32_t tx = x0 ^ x1;
  uint32_t ty = y0 ^ y1;
  // l(z) = rotl(z,16) ^ (z & 0x0000FFFF) ? Spec uses ℓ(x) = (x ≪ 16) ⊕ (x & 0xffff)
  // Careful: in Def. 2.1.2, ℓ(x) = (x ≪ 16) ⊕ (x & 0xffff). (≪ is rotation-left)
  // So: rotl32(x,16) ^ (x & 0xffff)
  tx = rotl32(tx,16) ^ (tx & 0xFFFFu);
  ty = rotl32(ty,16) ^ (ty & 0xFFFFu);

  // Feistel: inject to right-half
  x2 ^= ty;  y2 ^= tx;
  x3 ^= ty;  y3 ^= tx;

  // Branch permutation: rotate right-half left by 1, then swap halves
  // Right-half rotate: (x2,y2,x3,y3) -> (x3,y3,x2,y2)
  uint32_t rx2=x3, ry2=y3, rx3=x2, ry3=y2;

  // Swap halves: (left,right) -> (right,left)
  s[0]=rx2; s[1]=ry2; s[2]=rx3; s[3]=ry3;
  s[4]=x0;  s[5]=y0;  s[6]=x1;  s[7]=y1;
}

/* ---- One SPARKLE-256 step ---- */
static inline void sparkle256_step(uint32_t s[8], unsigned step_idx){
  // add step constants (sparse): y0 ^= c[step mod 8]; y1 ^= step
  s[1] ^= Cc[step_idx & 7u];
  s[3] ^= (uint32_t)step_idx;

  // Parallel Alzette on 4 branches under distinct c_i
  for(unsigned i=0;i<4;i++){
    alzette(&s[2*i+0], &s[2*i+1], Cc[2*i+0]);
  }

  L4(s);
}

/* ---- SPARKLE-256 with ns steps ---- */
static inline void sparkle256(uint32_t s[8], unsigned ns){
  for(unsigned i=0;i<ns;i++) sparkle256_step(s,i);
}
static inline void sparkle256_slim(uint32_t s[8]) { sparkle256(s,7);  }
static inline void sparkle256_big (uint32_t s[8]) { sparkle256(s,10); }

/* ---- Map 256-bit block <-> state words (little-endian, spec mapping) ---- */
static void bytes_to_state256(const uint8_t in[32], uint32_t s[8]){
  // spec packs bytes->words LE in order x0,y0,x1,y1,...
  for(int i=0;i<8;i++) s[i]=load32le(in+4*i);
}
static void state256_to_bytes(const uint32_t s[8], uint8_t out[32]){
  for(int i=0;i<8;i++) store32le(out+4*i, s[i]);
}

/* ---- ρ and ρ' on r=128 (two 64-bit halves but we treat 16 bytes) ----
 * FeistelSwap(S) = S2 || (S2 XOR S1), with S = S1||S2, |S1|=|S2|=64 bits? (Here |S|=r=128)
 * We'll do on 16 bytes, split into 8+8.
 */
static void feistel_swap_128(uint8_t S[16]){
  uint8_t T[16];
  memcpy(T, S, 16);
  // S1 = T[0..7], S2 = T[8..15]; output = S2 || (S2 ^ S1)
  memcpy(S,      T+8, 8);
  for(int i=0;i<8;i++) S[8+i] = T[8+i] ^ T[i];
}

/* ρ1(S,D) = FeistelSwap(S) ^ D ; ρ2(S,D) = S ^ D (both 128-bit) */
static void rho1(uint8_t out[16], const uint8_t S[16], const uint8_t D[16]){
  uint8_t T[16]; memcpy(T,S,16); feistel_swap_128(T);
  for(int i=0;i<16;i++) out[i] = T[i] ^ D[i];
}
static void rho2(uint8_t out[16], const uint8_t S[16], const uint8_t D[16]){
  for(int i=0;i<16;i++) out[i] = S[i] ^ D[i];
}
/* ρ1'(S,D) = FeistelSwap(S) ^ S ^ D ; ρ2'(S,D) = S ^ D  (for decryption) */
static void rho1_inv(uint8_t out[16], const uint8_t S[16], const uint8_t D[16]){
  uint8_t T[16]; memcpy(T,S,16); feistel_swap_128(T);
  for(int i=0;i<16;i++) out[i] = T[i] ^ S[i] ^ D[i];
}
static void rho2_inv(uint8_t out[16], const uint8_t S[16], const uint8_t D[16]){
  rho2(out,S,D);
}

/* Whitening for r=c case is identity: XOR inner part to outer part (spec §2.3.2). */

/* ---- Padding 10* to 128-bit block ---- */
static void pad128(uint8_t *dst16, const uint8_t *src, size_t len){
  memset(dst16, 0, 16);
  if(len) memcpy(dst16, src, len);
  dst16[len] = 0x80; /* append '1' then zeros */
}

/* ---- Helpers: split/join state S_L || S_R from 256-bit state words ---- */
static void get_SR_SL(const uint32_t S[8], uint8_t SL[16], uint8_t SR[16]){
  // state order: x0,y0,x1,y1 | x2,y2,x3,y3   (left 128, right 128)
  for(int i=0;i<4;i++){ store32le(SL+4*i, S[i]); }
  for(int i=0;i<4;i++){ store32le(SR+4*i, S[4+i]); }
}
static void put_SR_SL(uint32_t S[8], const uint8_t SL[16], const uint8_t SR[16]){
  for(int i=0;i<4;i++) S[i]   = load32le(SL+4*i);
  for(int i=0;i<4;i++) S[4+i] = load32le(SR+4*i);
}

/* XOR 128-bit buffer into another */
static inline void xor16(uint8_t *d, const uint8_t *a){ for(int i=0;i<16;i++) d[i]^=a[i]; }

/* ---- Domain constants (r=128). Spec encodes: A: (0/1) ⊕ (1<<2) = 4 or 5; M: (2/3) ⊕ (1<<2) = 6 or 7. ---- */
static void const_bytes(uint8_t out[16], uint8_t v){ /* v in {4,5,6,7} */
  memset(out,0,16); out[0]=v; /* little-endian LSByte */
}

/* ---- Schwaemm-128-128 Encrypt ---- */
int schwaemm128_128_encrypt(
  const uint8_t key[16], const uint8_t nonce[16],
  const uint8_t *ad, size_t ad_len,
  const uint8_t *msg, size_t msg_len,
  uint8_t *ct, uint8_t tag[16])
{
  uint8_t block[16], SL[16], SR[16], tmp[16], dom[16];
  uint8_t W[16]; /* whitening = SR for r=c */
  uint32_t S[8];
  uint8_t in[32];
  /* State init: S = SPARKLE256_big(N || K) */
  memcpy(in,  nonce,16);
  memcpy(in+16,key, 16);
  bytes_to_state256(in, S);
  sparkle256_big(S);

  /* Process Associated Data */
  size_t off = 0;
  while(ad_len >= 16){
    get_SR_SL(S, SL, SR);
    memcpy(W, SR, 16);
    rho1(tmp, SL, ad+off);
    xor16(tmp, SR);            /* + whitening (identity uses SR) */
    put_SR_SL(S, tmp, SR);
    sparkle256_slim(S);
    off += 16; ad_len -= 16;
  }
  /* Final AD block */
  {
    get_SR_SL(S, SL, SR);
    memcpy(W, SR, 16);
    if(ad_len>0){
      pad128(block, ad+off, ad_len);
      rho1(tmp, SL, block);
      xor16(tmp, SR);
      const_bytes(dom, 4u /*0 ^ (1<<2)*/);
    }else{
      /* empty last block */
      const_bytes(dom, 5u /*1 ^ (1<<2)*/);
      /* leave tmp as SL passed through rho1 with zero-block: FeistelSwap(SL) ^ 0 */
      rho1(tmp, SL, (const uint8_t[16]){0});
      xor16(tmp, SR);
    }
    /* big step separation */
    xor16(tmp, dom);
    xor16(SR, dom);
    put_SR_SL(S, tmp, SR);
    sparkle256_big(S);
  }

  /* Encrypt message */
  off = 0;
  while(msg_len >= 16){
    get_SR_SL(S, SL, SR);
    /* Cj = rho2(SL, Mj) */
    rho2(ct+off, SL, msg+off);
    /* state update */
    rho1(tmp, SL, msg+off);
    xor16(tmp, SR);
    put_SR_SL(S, tmp, SR);
    sparkle256_slim(S);
    off += 16; msg_len -= 16;
  }
  /* Final message block + Finalization */
  {
    get_SR_SL(S, SL, SR);
    if(msg_len>0){
      pad128(block, msg+off, msg_len);
      /* output partial C = trunc_r( rho2(SL, pad(M)) ) */
      rho2(tmp, SL, block);
      memcpy(ct+off, tmp, msg_len);
      const_bytes(dom, 6u /*2 ^ (1<<2)*/);
      /* state update uses rho1 with *unpadded* plaintext domain per Alg. 2.17: we pass padded here for symmetry with spec since r=128 */
      rho2(tmp, SL, block); /* for trunc, already computed; now get rho2(SL, M_*) to compute M_last for tag? */
      /* For state update before tag: use rho2(SL, M_last) truncated in spec; we follow Algorithm 2.17: C_last = trunc_r(ρ2(SL,M_last)); then:
         S <- SPARKLE256_big( (ρ1(SL,M_last) ⊕ SR ⊕ Const_M) || (SR ⊕ Const_M) ) */
      rho1(tmp, SL, block);
      xor16(tmp, SR);
    }else{
      /* empty message */
      const_bytes(dom, 7u /*3 ^ (1<<2)*/);
      /* no ciphertext bytes here */
      rho1(tmp, SL, (const uint8_t[16]){0});
      xor16(tmp, SR);
    }
    xor16(tmp, dom);
    xor16(SR, dom);
    put_SR_SL(S, tmp, SR);
    sparkle256_big(S);
  }

  /* Tag = SR ⊕ K */
  {
    get_SR_SL(S, SL, SR);
    for(int i=0;i<16;i++) tag[i] = SR[i] ^ key[i];
  }
  return 0;
}

/* ---- Schwaemm-128-128 Decrypt (returns 0 OK, -1 tag fail) ---- */
int schwaemm128_128_decrypt(
  const uint8_t key[16], const uint8_t nonce[16],
  const uint8_t *ad, size_t ad_len,
  const uint8_t *ct, size_t ct_len,
  uint8_t *msg, const uint8_t tag[16])
{
  uint8_t block[16], SL[16], SR[16], tmp[16], dom[16];
  uint32_t S[8];
  uint8_t in[32];
  /* Init */
  memcpy(in,  nonce,16);
  memcpy(in+16,key, 16);
  bytes_to_state256(in, S);
  sparkle256_big(S);

  /* AD */
  size_t off=0;
  while(ad_len >= 16){
    get_SR_SL(S, SL, SR);
    rho1(tmp, SL, ad+off);
    xor16(tmp, SR);
    put_SR_SL(S, tmp, SR);
    sparkle256_slim(S);
    off += 16; ad_len -= 16;
  }
  {
    get_SR_SL(S, SL, SR);
    if(ad_len>0){
      pad128(block, ad+off, ad_len);
      rho1(tmp, SL, block);
      xor16(tmp, SR);
      const_bytes(dom, 4u);
    }else{
      rho1(tmp, SL, (const uint8_t[16]){0});
      xor16(tmp, SR);
      const_bytes(dom, 5u);
    }
    xor16(tmp, dom); xor16(SR, dom);
    put_SR_SL(S, tmp, SR);
    sparkle256_big(S);
  }

  /* Message */
  off = 0;
  while(ct_len >= 16){
    get_SR_SL(S, SL, SR);
    /* Mj = rho2'(SL, Cj) = SL ^ Cj */
    rho2_inv(msg+off, SL, ct+off);
    /* update */
    rho1(tmp, SL, msg+off);
    xor16(tmp, SR);
    put_SR_SL(S, tmp, SR);
    sparkle256_slim(S);
    off += 16; ct_len -= 16;
  }
  {
    get_SR_SL(S, SL, SR);
    if(ct_len>0){
      /* recover padded M_last from partial C */
      pad128(block, (const uint8_t[1]){0}, 0); /* start clean */
      memset(block, 0, 16);
      memcpy(block, ct+off, ct_len);
      // Compute tmp = rho2'(SL, ?): but we only have truncated C; per Alg.2.17:
      // C_last = trunc_r(ρ2(SL, M_last)); we can reconstruct M_last by padding
      // Recreate full ρ2(SL, pad(M_last_plain)) then overwrite first ct_len with C_last to recover M_last_plain.
      // Instead, derive M_last_plain bytes directly:
      uint8_t rho2full[16]; pad128(block, ct+off /*placeholder*/, ct_len); /* we'll compute using ciphertext to back out plain */
      // Actually simpler: M_last = pad^{-1}( C_last ^ SL ) in the first ct_len bytes.
      for(size_t i=0;i<ct_len;i++) msg[off+i] = ct[off+i] ^ SL[i];
      const_bytes(dom, 6u);
      /* update with rho1(SL, pad(M_last)) as in encryption */
      pad128(block, msg+off, ct_len);
      rho1(tmp, SL, block);
      xor16(tmp, SR);
    }else{
      rho1(tmp, SL, (const uint8_t[16]){0});
      xor16(tmp, SR);
      const_bytes(dom, 7u);
    }
    xor16(tmp, dom); xor16(SR, dom);
    put_SR_SL(S, tmp, SR);
    sparkle256_big(S);
  }

  /* Verify tag: (SR ⊕ K) ?= tag */
  {
    uint8_t calc[16];
    get_SR_SL(S, SL, SR);
    for(int i=0;i<16;i++) calc[i] = SR[i] ^ key[i];
    uint32_t diff=0; for(int i=0;i<16;i++) diff |= (uint32_t)(calc[i]^tag[i]);
    return diff==0 ? 0 : -1;
  }
}