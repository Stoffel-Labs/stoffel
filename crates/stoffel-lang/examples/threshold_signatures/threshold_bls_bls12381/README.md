# Threshold BLS over BLS12-381

Threshold BLS example adapted from the StoffelVM fixture. It returns
`sig_g1(48) || pk_g2(96) || H(message)_g1(48)`. When client input is present,
the client-provided field share is opened as the message digest bytes before
hash-to-G1.
