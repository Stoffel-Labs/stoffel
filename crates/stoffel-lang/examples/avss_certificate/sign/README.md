# AVSS Certificate Sign

AVSS certificate threshold ECDSA signing example adapted from the StoffelVM
fixture. It consumes the persisted key from the keygen example and a client TBS
digest share, then sends `r || s` output shares to the client.
