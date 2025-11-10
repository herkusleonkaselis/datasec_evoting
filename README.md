# Cryptographic e-voting protocol demo
Pre-baked solution tool for the P170B127 Data Security midterm exam.
You must review and change the static parameters according to the problem ...
* `N_VOTERS` not expected to change, default 16 (4 bits)
* `N_CANDIDATES` not expected to change, default 3 (3*4=12 bits total)
* `CHOSEN_CANDIDATE_IDX` default 0
* `NUM_BITS_WORKING` default 14, used to compute nonce `r`. Formally it should be in `Z_N^*`, but the examples are magical.
* `N` expected to change, authority public key.

## Run
Change directory into the repo and run with:
```sh
cargo run
```
Tested with MSRV >= 1.84.0 (2024 ed.).

## Instructions
This is not feature-complete, the MTE requires multiple instances launched.
1. Run the first pass, cast your vote parameters `r`, `c`, minding potential reversal of indices. Emit `r`, `c`, wait for the local members to output `c`. Enter each `c`, including yours. Emit `Mul(c)`.
2. Run a second instance, ignore `r`, `c`. Enter `cMi`, accept `cMi` if it represents one vote only.
3. Run a third instance, ignore `r`, `c`. Enter `Mul(c)` and any valid `cMi`(s) from locale. Emit `prod(c)` as `Mul(c)*cMi`. emit `m_final`. Emit votes-per-candidate based on the given candidate encoding scheme (index represents right-to-left, aka bigger-nr-candidate-leftmost, but you may have to solve the inverse).
