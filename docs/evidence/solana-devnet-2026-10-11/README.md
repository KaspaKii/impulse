# I19 and I18 (Solana half) devnet run, 2026-10-11

Status: **passed on Solana devnet**, run 2026-10-11 from 22:00 UTC in the key holder's terminal with
throwaway keys (payer F9U9axxuz35ffk28tZp9r6C3n8yx3MEbibY5Yuydmg7M) (scripts/solana-devnet.sh at commit e8003fb). The payer was funded by hand from
faucet.solana.com after the scripted airdrops were refused. The throwaway keys were deleted when the
script exited; the unspent devnet SOL went with them.

Measured, from `run.log` (raw output, public addresses and signatures only) and `record.json`:

| Item | Value |
| --- | --- |
| impulse-solana program | 5G4u8j3dXuXvurs4mxJ2pNXLihHMgZRdomTSRhswi2Rf (final, authority none, 138552 bytes) |
| impulse-htlc program | EGzCZqc5fYqYqcUYWmXJpuqi4uqNWC91kgVozTc8BmqH (final, authority none, 33080 bytes) |
| CreateDvp (escrow at the term-sheet PDA) | QY8NZg6EGvGuazx4dfoKZFFfLf6nT7QKBgFdWktJs3JzkSxX1DiPay3WpL14GURGgQFmZodiEr9K9JSxrg68JEj |
| SettleDvp | 3hde8P5W93HaBo7oKAsmj3cQ7PvXWTfKG1VaCbGQDVUpyAaXpB1uLomu6GJjwcujuBF3Qt3aQpnLpjCQWVJFWGBg |
| HTLC claim | 2LLbn6XK6RaUBMMQbTMDq688THHfzi2qjQ2MrsAeaVx5nHWWTmM4HRbMFsUiAJLb3bnbA1tWXgWFkXBcYazujH7x |
| HTLC refund | itCpkG8nsMUCmBs8o2R9UEhgF37aH5xW2HeZX98dcav2CA553jAJXAea6dg84wsNREzxQLcGLhkFtqda8jLfjeP |

Checks the script made on chain, all passed:
- Settlement from one Impulse term sheet: escrow A held exactly 1000000 and escrow B exactly 2500000
  base units; after SettleDvp party A received exactly 2500000 of leg B, party B exactly 1000000 of
  leg A, both sources ended at 0, and the SwapDvp account and both escrows were closed.
- HTLC claim: the escrow held exactly 100000; after claim the recipient held exactly 100000 and the
  HTLC and its escrow were closed.
- HTLC refund: the escrow held exactly 100000; after the timeout the refund account was back to its
  pre-open balance and the HTLC and its escrow were closed.

Not shown by this run: the two mints are test SPL mints made by the script; TEST-USDC stands in for
USDC and is not Circle's USDC. The program IDs
here are throwaway devnet deployments, not the IDs in declare_id!. `run.mixed.log` is the file as written: it also holds lines from a second run
started 18 seconds later from another terminal (payer EbCswfc7gHTdjfrh2iHSoRZHQJbzzdsynCzEGvyAJ4Xp).
That payer was never funded, so it deployed nothing and sent no transaction; its lines there are the
airdrop refusals and faucet-wait messages naming that address. `run.log` is that file with the second run's lines removed and the first run's header restored from the key holder's terminal. Every program deployment and
transaction above belongs to the F9U9 run.

In `run.log` and `run.mixed.log` the local username in the file listings is redacted to `user`; nothing else in the logs is changed. No checksum file covers the logs.
