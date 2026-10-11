# MFTAH Protocol TODOs
Things to be accomplished near- or long-term for the MFTAH protocol interface.

- [ ] Unit-testing for cryptographic components (and some protocol endpoints)
- [ ] Full integration test, with notable regressions covered
- [ ] Pseudo-fuzz round-trip testing
  - Random inputs via `/dev/random` of varying lengths
  - Randomized CLI/protocol arguments (stream block sizes, non-stream mode, etc.)
  - Address sanitizer, symbols, etc. fully utilized
- [ ] Fuzz testing
  - [ ] Protocol encryption
  - [ ] Protocol decryption
  - [ ] Protocol stream encryption
  - [ ] Protocol stream decryption
