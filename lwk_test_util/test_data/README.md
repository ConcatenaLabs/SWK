# Test data

The block, block header, transaction and update vectors here are in Sequentia's wire format: an asset issuance carries its denomination byte (8 unless a test says otherwise) and a block header carries its 36-byte Bitcoin anchor, zero where the vector has no chain behind it.

They were made by re-encoding the content of vectors taken from Liquid. A transaction with an issuance has a different txid in this format, so each update's transactions, outpoints and txid lists follow it. The `wollet_status` an update carries is the status of the wallet after the updates before it, so the consecutive updates (`merge_updates/`, `update_many_txs.bin` and `update_v2_after_many_txs.bin`) were chained by applying them in order and writing each status in.
