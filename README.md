# executable-stealth-address-specs

This is a place to play around with stealth addresses and, more specifically, ERC-5564 using Python. The code is meant to provide executable specs for stealth addresses and the ERC to help getting started with experimenting or more sophisticated implementation.

### Sender and Recipient Stealth Address Generation and Parsing

This guide walks through the process of generating and parsing stealth addresses using Python.

#### Sender

Generate the ephemeral private key and corresponding public key.

```python
from main import *

aPriv = generate_random_private_key() # ephemeral private Key
aPub = priv_to_pub(aPriv) # ephemeral public Key
print("aPriv:", aPriv)
print("aPub:", aPub)
```

#### Recipient
Generate the spending and scanning private and public keys, then create a stealth meta-address.

```python
bPrivSp = generate_random_private_key() # spending private key
bPrivSc = generate_random_private_key() # scanning private key

bPubSp = priv_to_pub(bPrivSp) # spending public key
bPubSc = priv_to_pub(bPrivSc) # scanning public key

stealthMA = generate_stealth_meta_address(bPubSp, bPubSc)

print("bPrivSp:", bPrivSp)
print("bPrivSc:", bPrivSc)
print("bPubSp:", bPubSp)
print("bPubSc:", bPubSc)
print("stealthMA:", stealthMA)
```

Sender computes stealth address and necessary information for the recipient:

```python
stAddress, ephemeralPublicKey, viewTag = generate_stealth_address_info_from_meta_address(stealthMA, aPriv)


print("stAddress:", stAddress)
print("ephemeralPublicKey:", ephemeralPublicKey)
print("viewTag:", viewTag)
```

Recipient parses all events and collects the ephemeral pubkey, the stealth addresses, and view tags logged

```python
moreRandomPrivateKeys = [generate_random_private_key() for i in range(1,101)]
moreRandomPublicKeys = [priv_to_pub(i) for i in moreRandomPrivateKeys]
moreRandomStealthAddresses = [pubkey_to_address(i) for i in moreRandomPublicKeys]
moreRandomViewTags = [i for i in range(len(moreRandomStealthAddresses))]

found, parsed = parse(
    [ephemeralPublicKey]+moreRandomPublicKeys, 
    [stAddress] + moreRandomStealthAddresses, 
    [viewTag] + moreRandomViewTags, 
    bPrivSc, 
    bPubSp
)

matching_dh_secrets = [i[0] for i in found]
stealthPrivateKeys = compute_stealth_address_private_key(matching_dh_secrets, bPrivSp)

for i in stealthPrivateKeys:
    print(hex(i))
```

The above script demonstrates how a sender and recipient can generate and parse stealth addresses for private transactions. Each step is annotated for clarity. Adjust the code as necessary for your specific use case.


