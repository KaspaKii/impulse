# Copyright (c) 2026 the Impulse authors. A KiiLabs product. Licensed under the Apache License, Version 2.0.
# Shared helpers of the shell scripts that drive the CLI (I7). Sourced, not run.
# Holds no endpoint and no key: every node URL, key file and token comes from the user.

die() { echo "$(basename "$0"): $*" >&2; exit 1; }

# The value of the first "key: value" line of $2 whose key is $1.
field() { printf '%s\n' "$2" | sed -n "s/^$1: //p" | head -n 1; }

hex32() { printf '%s' "$1" | grep -Eq '^[0-9a-f]{64}$'; }

# 32 random bytes as 64 lowercase hex digits (a trade reference, not a key).
random_ref() { od -An -tx1 -N32 /dev/urandom | tr -d ' \n'; }

# A KAS destination (P2PK of an x-only key) and a KCC-20 owner (that key), in the JSON form of
# spec/ENCODING.md.
kas_to() { printf '{"kind":"kas","version":0,"script":"20%sac"}' "$1"; }
owner_is() { printf '{"kind":"kcc20","identifier_type":"pubkey","identifier":"%s"}' "$1"; }
off_chain() { printf '{"kind":"off_chain"}'; }
kcc20_leg() { # covenant template_hash prefix_len suffix_len amount
  printf '{"kind":"kcc20","covenant_id":"%s","template_hash":"%s","template_prefix_len":%s,"template_suffix_len":%s,"amount":"%s"}' "$1" "$2" "$3" "$4" "$5"
}
kas_leg() { printf '{"kind":"kas","amount":"%s"}' "$1"; }
external_leg() { printf '{"kind":"external","amount":"%s"}' "$1"; }

# draft <file> <network> <vault|direct> <seller> <buyer> <authority|null> <asset_leg> <cash_leg>
#       <buyer_delivery> <seller_proceeds> <seller_refund> <buyer_refund> <expiry_daa>
#       <revocable|earmarked>
# The nonce is left null: `impulse terms new` draws it.
draft() {
  local auth
  if [ "$6" = null ]; then auth=null; else auth="\"$6\""; fi
  cat > "$1" <<EOF
{"version":1,"network":"$2","settlement_mode":"$3","nonce":null,"seller_key":"$4","buyer_key":"$5","authority_key":$auth,"asset_leg":$7,"cash_leg":$8,"buyer_delivery":$9,"seller_proceeds":${10},"seller_refund":${11},"buyer_refund":${12},"earliest_daa":null,"expiry_daa":"${13}","funding_mode":"${14}","trade_ref":"$(random_ref)"}
EOF
}
