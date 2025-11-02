# Cryptographic e-voting protocol demo
Pre-baked solution for the P170B127 Data Security midterm exam.
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
