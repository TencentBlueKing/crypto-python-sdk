import base64

LEGACY_PLAINTEXT = b"37045a07-8d63-494e-b2d1-8ded581b675a\n"

# This key is retained only because the two historical SM2 ciphertexts depend on it.
SM2_PRIVATE_KEY = """-----BEGIN EC PRIVATE KEY-----
MHcCAQEEIET20O7suONqg1gYrd7LTiImqlYEdcqJgkmPq0QkCRLMoAoGCCqBHM9V
AYItoUQDQgAEGgYRs1JjB722dmwUQQM2DGHuDNvAUQkU/z4an25t6L6tD5FZFg6f
uSE2/htPEaquQc4tbQWi9hdXxrq4l+mp+Q==
-----END EC PRIVATE KEY-----"""

# This key is retained only because the C++ and Node.js SM4 ciphertexts depend on it.
SM4_CROSS_LANGUAGE_KEY = b"Tencent"

LEGACY_CIPHERTEXTS = {
    "text.sm2.nodejs.encrypt": base64.b64decode(
        "MIGNAiBm8N9L7uqIeZMHDhJh40YPpwuyMTc4ByMxagGJWweqLgIgJFPNlgnBndLCAbCzUfXFMe5ha/1h0hDF16PDDBkWdPEE"
        "IBzdcK+3AS+r6RQUBQOSj7yzoHFHqY/4/Uw95ZSdfGJzBCW0YNjS8004Ea4a3SRtPsS4biMEwnuwNBPvIGOCId431WoVHjx7"
    ),
    "text.sm2.python.encrypt": base64.b64decode(
        "MIGOAiA8PqAoJO3A1NM39iDCwDw/W47WUfskeeLx6ZhjhBdfxwIhANX7NshCk1G6kVDwzA9lpUjkVG6SfO3kiUMFz8lNiSRJ"
        "BCAan73OhB+X6SOyNyZBBeskcCjoIf4XID23lPduQpk0AQQlPxZ4h9G4B8SfodSwqG+gfsMltSKZN9XFr9DhcqMSau1uAVNb1"
        "w=="
    ),
    "text.sm4.cpp.encrypt": base64.b64decode(
        "AAECAwQFBgcICQoLDA0OD79fvBhRGszK/64wiEdPwkipGi9wuuyprc+RjeptHDV+t9qIIzE="
    ),
    "text.sm4.java.encrypt": base64.b64decode(
        "ttFi9EMQ20KBtBvABsTRluLR86wYNKoaIO3x2hqfGdZfiWm2O33FPPNtGpRrHiQ9IaIuO3U="
    ),
    "text.sm4.nodejs.encrypt": base64.b64decode(
        "AAECAwQFBgcICQoLDA0OD79fvBhRGszK/64wiEdPwkipGi9wuuyprc+RjeptHDV+t9qIIzE="
    ),
}
