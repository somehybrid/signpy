pub(crate) fn const_time_eq(a: &[u8], b: &[u8]) -> bool {
    let mut temp = 0;

    for (i, j) in a.iter().zip(b.iter()) {
        temp |= i ^ j;
    }

    temp == 0
}
