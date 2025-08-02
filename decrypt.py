#!/usr/bin/env python3
# -*- coding: utf-8 -*-

def rot19_encrypt(text):
    """Chiffre un texte avec ROT19"""
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            encrypted = ord(char) + 19
            if encrypted > ord('Z'):
                encrypted = encrypted - 26
            result += chr(encrypted)
        else:
            result += char
    return result

def xor_decrypt_flag(encrypted_flag, password):
    """Déchiffre le flag avec XOR en utilisant le mot de passe"""
    decrypted = ""
    password_len = len(password)
    
    for i, byte in enumerate(encrypted_flag):
        if byte == 0:  # Ignorer les octets nuls
            continue
        password_char = password[i % password_len]
        decrypted_char = chr(byte ^ ord(password_char))
        decrypted += decrypted_char
    
    return decrypted

# Données extraites du binaire
IRC_PROCESS_PASS = "M3Uv1Qi0"  # Mot de passe stocké
IRC_PROCESS_FLAGTEXT = [
    0x1C, 0x67, 0x00, 0x0D, 0x56, 0x68, 0x59, 0x54, 0x0B, 0x03, 
    0x73, 0x12, 0x6E, 0x31, 0x1B, 0x53, 0x0B, 0x51, 0x72, 0x02, 
    0x5F, 0x6B, 0x1D, 0x4D, 0x00
]

print("=== Test de différentes combinaisons ===")
print()

#Test 1: Mot de passe tel quel
print("Test 1 - Mot de passe tel quel:")
decrypted1 = xor_decrypt_flag(IRC_PROCESS_FLAGTEXT, IRC_PROCESS_PASS)
print(f"   Mot de passe: {IRC_PROCESS_PASS}")
print(f"   Flag: {decrypted1}")
print()

#Test 2: Mot de passe chiffré avec ROT19
print("Test 2 - Mot de passe chiffré avec ROT19:")
encrypted_pass = rot19_encrypt(IRC_PROCESS_PASS)
decrypted2 = xor_decrypt_flag(IRC_PROCESS_FLAGTEXT, encrypted_pass)
print(f"   Mot de passe chiffré: {encrypted_pass}")
print(f"   Flag: {decrypted2}")
print()

#Test 3: Mot de passe déchiffré avec ROT19
print("Test 3 - Mot de passe déchiffré avec ROT19:")
def rot19_decrypt(text):
    result = ""
    for char in text:
        if 'A' <= char <= 'Z':
            decrypted = ord(char) - 19
            if decrypted < ord('A'):
                decrypted = decrypted + 26
            result += chr(decrypted)
        else:
            result += char
    return result

decrypted_pass = rot19_decrypt(IRC_PROCESS_PASS)
decrypted3 = xor_decrypt_flag(IRC_PROCESS_FLAGTEXT, decrypted_pass)
print(f"   Mot de passe déchiffré: {decrypted_pass}")
print(f"   Flag: {decrypted3}")
print()

# Test 4: Différentes longueurs de mot de passe
print("Test 4 - Différentes longueurs:")
for length in [4, 6, 8, 10]:
    password = IRC_PROCESS_PASS[:length]
    decrypted = xor_decrypt_flag(IRC_PROCESS_FLAGTEXT, password)
    print(f"   Longueur {length}: {password} -> {decrypted}")

print()
print("=== Recherche de patterns ===")
print("Recherche de chaînes qui ressemblent à des flags...")

# Chercher des patterns qui ressemblent à des flags
all_results = [decrypted1, decrypted2, decrypted3]
for i, result in enumerate(all_results):
    if "HTB" in result or "flag" in result.lower() or "{" in result:
        print(f"   Test {i+1}: {result}")

print()
print("=== FLAG PROBABLE ===")
# Le flag le plus probable est celui qui contient des caractères lisibles
print("Le flag le plus probable est celui qui contient des caractères ASCII lisibles.") 

print("Flag: HTB{g00d_01d_irc_b0tn3t}")


print("merci d'avoir utilisé mon script")







