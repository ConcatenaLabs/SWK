A 3-of-5 multisig wallet (`desc`) and a pset that spends one explicit output of it.

`sX_pset.base64` is that pset signed by signer X alone, so each has 1 signature and any 3 of them combine into a pset that finalizes. The signing keys were generated for the vector and discarded; the signatures are made by `SwSigner`, over the Sequentia signature hash.
