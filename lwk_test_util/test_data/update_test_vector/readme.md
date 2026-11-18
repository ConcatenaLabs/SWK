`000000000000` contains an update encrypted with the key derived from the descriptor `desc`, in the format of a wallet's update file (a random nonce, then the ciphertext). It pins that updates written in that format stay readable.

`desc` contains the descriptor used for encryption of `000000000000`


`desc2` contains a descriptor
`update.base64` contains an encrypted (with `desc2`) update encoded in base64
