//! Randomised totality check: no 64-byte input may panic the decoder, and any
//! input it accepts must round-trip to an equal request.
use sync_wire::{Request, REQUEST_LEN};

/// A tiny xorshift PRNG, so this needs no dev-dependency.
struct Rng(u64);
impl Rng {
    fn next(&mut self) -> u64 {
        let mut x = self.0;
        x ^= x << 13;
        x ^= x >> 7;
        x ^= x << 17;
        self.0 = x;
        x
    }
}

#[test]
fn random_frames_never_panic_and_accepted_ones_round_trip() {
    let mut rng = Rng(0x9E37_79B9_7F4A_7C15);
    let mut accepted = 0u64;
    for _ in 0..500_000 {
        let mut frame = [0u8; REQUEST_LEN];
        // Bias toward structurally valid frames half the time so the accept
        // path is actually exercised.
        if rng.next() & 1 == 0 {
            frame[0..4].copy_from_slice(b"SYNC");
            frame[4] = 1;
            frame[5] = (rng.next() % 4) as u8;
        }
        for chunk in frame.chunks_mut(8) {
            let r = rng.next().to_le_bytes();
            for (i, b) in chunk.iter_mut().enumerate() {
                if rng.next() & 1 == 0 {
                    *b = r[i];
                }
            }
        }
        if let Ok(req) = Request::decode(&frame) {
            accepted += 1;
            // Anything accepted must re-encode and decode to itself.
            let again = Request::decode(&req.encode()).expect("re-encode must decode");
            assert_eq!(again, req, "round-trip mismatch for {req:?}");
        }
    }
    assert!(
        accepted > 0,
        "fuzzer never produced an acceptable frame; test is vacuous"
    );
}

#[test]
fn every_single_bit_of_an_all_zero_frame_is_exercised() {
    // All-zero frame is a near-miss; flipping each of the 512 bits must never
    // panic and must be decided one way or the other without allocating.
    let base = [0u8; REQUEST_LEN];
    for byte in 0..REQUEST_LEN {
        for bit in 0..8 {
            let mut f = base;
            f[byte] |= 1 << bit;
            let _ = Request::decode(&f);
        }
    }
}
