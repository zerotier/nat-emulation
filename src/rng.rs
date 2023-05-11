pub fn xorshift64star(state: &mut u64) -> u64 {
    *state ^= *state >> 12;
    *state ^= *state << 25;
    *state ^= *state >> 27;
    return state.wrapping_mul(0x2545F4914F6CDD1Du64);
}
