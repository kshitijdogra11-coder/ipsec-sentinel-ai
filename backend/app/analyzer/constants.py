"""IPsec / IKE protocol constants (RFC 7296, RFC 2409, RFC 4303, IANA registries).

Shared by the packet parser, the testbed generator and the assessment engine.
"""

# ---------------------------------------------------------------- IKEv2 ----
IKEV2_EXCHANGE = {34: "IKE_SA_INIT", 35: "IKE_AUTH", 36: "CREATE_CHILD_SA", 37: "INFORMATIONAL"}
IKEV1_EXCHANGE = {2: "Main Mode", 4: "Aggressive Mode", 5: "Informational", 32: "Quick Mode", 33: "New Group"}

IKEV2_PAYLOAD = {
    0: "NONE", 33: "SA", 34: "KE", 35: "IDi", 36: "IDr", 37: "CERT", 38: "CERTREQ",
    39: "AUTH", 40: "Nonce", 41: "Notify", 42: "Delete", 43: "VendorID", 44: "TSi",
    45: "TSr", 46: "SK", 47: "CP", 48: "EAP", 53: "SKF",
}
IKEV1_PAYLOAD = {
    0: "NONE", 1: "SA", 2: "Proposal", 3: "Transform", 4: "KE", 5: "ID", 6: "CERT",
    7: "CR", 8: "HASH", 9: "SIG", 10: "Nonce", 11: "Notify", 12: "Delete", 13: "VendorID",
    20: "NAT-D", 21: "NAT-OA",
}

# Transform types
T_ENCR, T_PRF, T_INTEG, T_DH, T_ESN = 1, 2, 3, 4, 5

IKEV2_ENCR = {
    2: "DES", 3: "3DES", 11: "NULL", 12: "AES-CBC", 13: "AES-CTR", 14: "AES-CCM-8",
    16: "AES-CCM-16", 18: "AES-GCM-8", 19: "AES-GCM-12", 20: "AES-GCM-16",
    23: "CAMELLIA-CBC", 28: "CHACHA20-POLY1305",
}
IKEV2_PRF = {1: "HMAC-MD5", 2: "HMAC-SHA1", 4: "AES128-XCBC", 5: "HMAC-SHA2-256",
             6: "HMAC-SHA2-384", 7: "HMAC-SHA2-512"}
IKEV2_INTEG = {0: "NONE", 1: "HMAC-MD5-96", 2: "HMAC-SHA1-96", 5: "AES-XCBC-96",
               12: "HMAC-SHA2-256-128", 13: "HMAC-SHA2-384-192", 14: "HMAC-SHA2-512-256"}
DH_GROUPS = {
    0: "NONE", 1: "MODP-768", 2: "MODP-1024", 5: "MODP-1536", 14: "MODP-2048",
    15: "MODP-3072", 16: "MODP-4096", 17: "MODP-6144", 18: "MODP-8192",
    19: "ECP-256", 20: "ECP-384", 21: "ECP-521", 24: "MODP-2048/256",
    31: "Curve25519", 32: "Curve448",
}
# Public value length (bytes) inside KE payload for each DH group
DH_KE_LEN = {1: 96, 2: 128, 5: 192, 14: 256, 15: 384, 16: 512, 17: 768, 18: 1024,
             19: 64, 20: 96, 21: 132, 24: 256, 31: 32, 32: 56}
# Approximate symmetric-equivalent security strength (bits) - NIST SP 800-57
DH_STRENGTH = {1: 56, 2: 80, 5: 96, 14: 112, 15: 128, 16: 152, 17: 176, 18: 200,
               19: 128, 20: 192, 21: 256, 24: 112, 31: 128, 32: 224}

IKEV2_NOTIFY = {
    14: "NO_PROPOSAL_CHOSEN", 24: "AUTHENTICATION_FAILED", 16384: "INITIAL_CONTACT",
    16388: "NAT_DETECTION_SOURCE_IP", 16389: "NAT_DETECTION_DESTINATION_IP",
    16390: "COOKIE", 16391: "USE_TRANSPORT_MODE", 16404: "MOBIKE_SUPPORTED",
    16430: "IKEV2_FRAGMENTATION_SUPPORTED", 16431: "SIGNATURE_HASH_ALGORITHMS",
    16435: "CHILDLESS_IKEV2_SUPPORTED",
}

# ---------------------------------------------------------------- IKEv1 ----
IKEV1_ATTR = {1: "Encryption", 2: "Hash", 3: "AuthMethod", 4: "GroupDesc",
              11: "LifeType", 12: "LifeDuration", 14: "KeyLength"}
IKEV1_ENCR = {1: "DES", 5: "3DES", 7: "AES-CBC"}
IKEV1_HASH = {1: "MD5", 2: "SHA1", 4: "SHA2-256", 5: "SHA2-384", 6: "SHA2-512"}
IKEV1_AUTH = {1: "PSK", 3: "RSA-SIG", 9: "ECDSA-256", 65001: "XAUTH-PSK"}

# Well-known Vendor IDs (hex, prefix match)
VENDOR_IDS = {
    "882fe56d6fd20dbc2251613b2ebe5beb": "strongSwan",
    "4a131c81070358455c5728f20e95452f": "RFC 3947 NAT-T",
    "afcad71368a1f1c96b8696fc77570100": "Dead Peer Detection v1.0",
    "12f5f28c457168a9702d9fe274cc0100": "Cisco Unity",
    "09002689dfd6b712": "XAUTH",
    "1e2b516905991c7d7c96fcbfb587e461": "Microsoft Windows",
    "4048b7d56ebce88525e7de7f00d6c2d3": "IKE Fragmentation",
    "90cb80913ebb696e086381b5ec427b1f": "draft-ietf-ipsec-nat-t-ike-02",
    "4f45606c50487c5662707575": "Libreswan",
}

# ---------------------------------------------------------------- ESP ------
# name -> (iv_len, icv_len_if_aead, block_size)
ESP_CIPHERS = {
    "AES-CBC": (16, 0, 16),
    "AES-GCM": (8, 16, 4),
    "3DES": (8, 0, 8),
    "NULL": (0, 0, 4),
}
ESP_INTEG_ICV = {"HMAC-SHA1-96": 12, "HMAC-MD5-96": 12, "HMAC-SHA2-256-128": 16,
                 "HMAC-SHA2-512-256": 32, "NONE": 0}

IP_PROTO = {1: "ICMP", 4: "IPv4", 6: "TCP", 17: "UDP", 41: "IPv6", 50: "ESP", 51: "AH", 58: "ICMPv6"}

TRAFFIC_CLASSES = ["voip", "whatsapp", "email", "web", "icmp", "video"]
