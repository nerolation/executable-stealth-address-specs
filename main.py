import hashlib
from py_ecc.secp256k1 import *
import sha3
import ecdsa
import os
from eth_account import Account
from typing import NewType
from functools import wraps
from dataclasses import dataclass

SECP256K1_ORDER = int(0xFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFFEBAAEDCE6AF48A03BBFD25E8CD0364141)

USE_VIEWTAGS = True
LOGGING = False

def print_function_name(func):
    @wraps(func)
    def wrapper(*args, **kwargs):
        if not LOGGING:
            return func(*args, **kwargs)
        print(f"Executing function: {func.__name__}")
        return func(*args, **kwargs)
    return wrapper
pfn = print_function_name

PrivateKey = NewType('PrivateKey', int)
PublicKeyPoint = NewType('PublicKeyPoint', int)
HashBelowOrder = NewType('HashBelowOrder', int)
EthAddress = NewType('EthAddress', str)
ViewTag = NewType('ViewTag', int)
HexString = NewType('HexString', str)
CompressedPublicKey = NewType('CompressedPublicKey', str)
StealthMetaAddress = NewType('StealthMetaAddress', str)

@dataclass
class PublicKey:
    x: PublicKeyPoint = 0
    y: PublicKeyPoint = 0
    xy: CompressedPublicKey = 0
        
    @pfn
    def compress(self) -> str:
        # Determine the prefix based on the parity of y
        prefix = '02' if self.y % 2 == 0 else '03'  # '02' for even y, '03' for odd y
        # Convert x to a hex string, remove '0x' prefix, and pad to 64 characters
        x_hex = hex(self.x)[2:].zfill(64)
        # Concatenate prefix and x-coordinate
        return CompressedPublicKey(prefix + x_hex)
    
    @pfn
    def uncompress(self) -> 'PublicKey':
        publicKey = ecdsa.VerifyingKey.from_string(bytes.fromhex(self.xy), curve=ecdsa.SECP256k1)
        publicKey = publicKey.pubkey.point
        return PublicKey(publicKey.x(), publicKey.y())

@dataclass
class DHSecret(PublicKey):
    pass

@dataclass
class InvalidStealthMetaAddress(Exception):
    message: str = "Invalid Stealth Meta Address format"

@pfn
def generate_random_private_key() -> PrivateKey:
    # Generate a random 32 bytes (256 bits)
    random_bytes = os.urandom(32)
    # Convert the random bytes to an integer
    random_int = int.from_bytes(random_bytes, 'big')
    # Modulo it by the order of the curve to ensure it's a valid private key
    private_key = random_int % SECP256K1_ORDER
    # Ensure the private key is not 0
    if private_key == 0:
        return generate_random_private_key()

    return PrivateKey(private_key)

@pfn
def to_hex(i: int) -> HexString:
    return hex(i)

@pfn
def priv_to_pub(privateKey: PrivateKey) -> PublicKey:
    # Convert the private key integer to a 32-byte big-endian representation and get the public key
    return PublicKey(*secp256k1.privtopub(privateKey.to_bytes(32, 'big')))

@pfn
def pubkey_add(publicKey: PublicKey, publicKey2: PublicKey) -> PublicKey:
    # Add two public keys together by doing an EC addition
    return PublicKey(
        *secp256k1.add(
            (publicKey.x, publicKey.y),
            (publicKey2.x, publicKey2.y)
        )
    )
    
@pfn
def pubkey_mul(publicKey: PublicKey, x: int) -> PublicKey:
    # Multiply two public keys by doing an EC multiplication
    return PublicKey(*secp256k1.multiply((publicKey.x, publicKey.y), x))

@pfn
def hash_public_key(publicKey: PublicKey) -> HashBelowOrder:
    # Hash point to a scalar
    return HashBelowOrder(
        int(
            sha3.keccak_256(
                publicKey.x.to_bytes(32, "big") + 
                publicKey.y.to_bytes(32, "big")
            ).hexdigest(), 
            16
        ) % SECP256K1_ORDER
    )

@pfn
def pubkey_to_address(publicKey: PublicKey) -> EthAddress:
    # Convert public key to ethereum address
    return EthAddress(
        "0x" + sha3.keccak_256(
            publicKey.x.to_bytes(32, "big") +
            publicKey.y.to_bytes(32, "big")
        ).hexdigest()[-40:]
    )


@pfn
def parse_stealth_meta_address(stealthMetaAddress: StealthMetaAddress) -> (PublicKey):
    # Parse a stealth meta address and return the spending and scanning public keys
    if not stealthMetaAddress.startswith("st:eth:0x"):
        raise InvalidStealthMetaAddress
    if not len(stealthMetaAddress) == 66*2+2+7:
        raise InvalidStealthMetaAddress
    
    sma_string = stealthMetaAddress.split(":")[-1][2:] # This gets the part after 'st:eth:0x'
    publicKeySp, publicKeySc = sma_string[:66], sma_string[66:]
    return PublicKey(xy=publicKeySp).uncompress(), PublicKey(xy=publicKeySc).uncompress()

@pfn
def generate_stealth_meta_address(bPubSp: PublicKey, bPubSc: PublicKey) -> StealthMetaAddress:
    # Generate a stealth meta address from two uncompressed public keys
    return StealthMetaAddress("st:eth:0x" + bPubSp.compress() + bPubSc.compress())
    
@pfn
def compute_ephemeral_public_key(ephemeralPrivateKey: PrivateKey) -> PublicKey:
    # Compute a public key from a random private key
    return priv_to_pub(ephemeralPrivateKey)

@pfn
def compute_dh_secret(publicKey: PublicKey, ephemeralPrivateKey: PrivateKey) -> PublicKey:
    # Compute the Diffie-Hellman secret
    return pubkey_mul(publicKey, ephemeralPrivateKey)
    
@pfn
def hashed_dh_secret_to_point(dhSecretHash: HashBelowOrder) -> PublicKey:
    # Put the hashed dh secret onto the curve
    return priv_to_pub(dhSecretHash)

@pfn
def hash_dh_secret(dhSecret: PublicKey) -> HashBelowOrder:
    # Hash dh secret to convert it form a public key to a scalar
    return hash_public_key(dhSecret)

@pfn
def retrieve_view_tag(dhSecretHash: HashBelowOrder) -> ViewTag:
    # Get the first byte to be used as a view tag
    return ViewTag(dhSecretHash.to_bytes(32, "big")[0])

@pfn
def compute_stealth_public_key_from_dh_point(dhSecretPoint: PublicKey, publicKey: PublicKey) -> PublicKey:
    # Compute the stealth address public key by adding the spending pub key to the point of the dh secret
    return pubkey_add(publicKey, dhSecretPoint)

@pfn
def check_view_tag(dhSecretHash: HashBelowOrder, comparisonTag: ViewTag):
    # Check if the view tag matches
    retrievedViewTag = retrieve_view_tag(dhSecretHash)
    return True if retrievedViewTag == comparisonTag else False

@pfn
def compute_stealth_address_from_recipient_info(
    publicKeySpending: PublicKey, 
    publicKeyScanning: PublicKey, 
    ephemeralPrivateKey: PrivateKey
) -> (EthAddress, PublicKey, ViewTag):
    # Generate necessary information for a stealth address transaction
    dhSecret = compute_dh_secret(publicKeyScanning, ephemeralPrivateKey)
    dhSecretHash = hash_dh_secret(dhSecret)
    viewTag = retrieve_view_tag(dhSecretHash)  
    dhSecretPoint = hashed_dh_secret_to_point(dhSecretHash)
    stealthAddressPublicKey = compute_stealth_public_key_from_dh_point(dhSecretPoint, publicKeySpending)
    stealthAddress = pubkey_to_address(stealthAddressPublicKey)
    ephemeralPublicKey = compute_ephemeral_public_key(ephemeralPrivateKey)
    return stealthAddress, ephemeralPublicKey, viewTag

@pfn
def generate_stealth_address_info_from_meta_address(
    # Take stealth meta address and random private key to generate info for stealth address transaction
    stealthMetaAddress: StealthMetaAddress, 
    ephemeralPrivateKey: PrivateKey
) -> (EthAddress, PublicKey, ViewTag):
    publicKeySpending, publicKeyScanning = parse_stealth_meta_address(stealthMetaAddress)
    return compute_stealth_address_from_recipient_info(publicKeySpending, publicKeyScanning, ephemeralPrivateKey)
    
    
def parse_single_event(pubkey, stA, viewtag, scanningPrivateKey, spendingPublicKey):
    # Check if inputed stealth address matches the derived one
    dhSecret = compute_dh_secret(pubkey, scanningPrivateKey)
    dhSecretHash = hash_dh_secret(dhSecret)
    if not check_view_tag(dhSecretHash, viewtag):
        return None, stA

    dhSecretPoint = hashed_dh_secret_to_point(dhSecretHash)
    stealthAddressPublicKey = compute_stealth_public_key_from_dh_point(dhSecretPoint, spendingPublicKey)
    stealthAddress = pubkey_to_address(stealthAddressPublicKey)
    if stealthAddress == stA:
        print(f"Stealth address found | {stA}")
        return dhSecretHash, stA
    return None, stA
@pfn
def parse(
    publicKeys: [PublicKey], 
    stealthAddresses: [EthAddress],
    viewTags: [ViewTag],
    scanningPrivateKey: PrivateKey, 
    spendingPublicKey: PublicKey,
) -> ([(HashBelowOrder, EthAddress)], [EthAddress]):
    # Parse over multiple events and check for valid stealth addresses
    found = [] # contains the dh secrets of all successfully derived stealth addresses
    parsed = [] # contains all stealth addresses parse (can be used for caching)
    for pubkey, stA, viewtag in zip(publicKeys, stealthAddresses, viewTags):
        dhSecretHash, stA = parse_single_event(pubkey, stA, viewtag, scanningPrivateKey, spendingPublicKey)
        if dhSecretHash:
            found.append((dhSecretHash, stA)) # store dh secret to derive the stealth address private key later
        parsed.append(stA)
    return found, parsed

@pfn
def compute_stealth_address_private_key(
    dhSecrets: [HashBelowOrder], 
    spendingPrivateKey: PrivateKey
) -> [PrivateKey]:
    # Derive stealth address private keys from the spending private key and the inputed dh secrets
    return [(spendingPrivateKey + dh_secret) % SECP256K1_ORDER for dh_secret in dhSecrets]
        