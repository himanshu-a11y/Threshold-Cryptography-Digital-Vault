"""
Data Conversion Utility for Digital Vault

Handles secure conversion of complex UTF-8 strings (passwords, secret notes, etc.)
into Large Integers via hex encoding, making them compatible with mathematical algorithms
like Shamir's Secret Sharing. Provides lossless reconstruction back to the original strings.
"""


def string_to_int(secret_string: str) -> int:
    """
    Converts a complex UTF-8 string into a large integer using hex encoding.

    Process:
    1. Encodes the string into UTF-8 bytes.
    2. Converts the byte array into a hexadecimal string representation.
    3. Interprets the hex string as a base-16 large integer.

    Args:
        secret_string: The original string data (e.g., password or secret note).

    Returns:
        A large integer representing the string data.
    """
    # Step 1: Encode string to UTF-8 bytes
    utf8_bytes = secret_string.encode("utf-8")

    # Step 2: Convert bytes to hex string
    hex_str = utf8_bytes.hex()

    # Step 3: Convert hex string to large integer
    # Using base 16 interpretation
    return int(hex_str, 16)


def int_to_string(secret_int: int) -> str:
    """
    Decodes a large integer back into the original UTF-8 string without data loss.

    Process:
    1. Converts the integer back to a hexadecimal string.
    2. Ensures even length padding for valid byte boundaries.
    3. Converts the hex string back to UTF-8 bytes.
    4. Decodes the bytes to reconstruct the original string.

    Args:
        secret_int: The large integer representation of the secret.

    Returns:
        The fully reconstructed original UTF-8 string.
    """
    if secret_int < 0:
        raise ValueError("Secret integer must be non-negative.")
    
    # Handle the special case of an empty string resulting in integer 0
    if secret_int == 0:
        return ""

    # Step 1: Convert integer to hex string, removing the '0x' prefix
    hex_str = hex(secret_int)[2:]

    # Step 2: Ensure even length for proper byte deserialization
    # If the integer representation dropped a leading zero from the first byte's hex, restore it.
    if len(hex_str) % 2 != 0:
        hex_str = "0" + hex_str

    # Step 3: Convert hex string back to bytes
    utf8_bytes = bytes.fromhex(hex_str)

    # Step 4: Decode bytes back to UTF-8 string
    return utf8_bytes.decode("utf-8")


if __name__ == "__main__":
    print("=" * 70)
    print("Digital Vault Data Converter - Verification & Demonstration")
    print("=" * 70)

    # Test Case 1: Standard complex string with symbols
    original_secret = "Vault-Pass!@#2026 | Core Secret Note: System Config Secured"
    print(f"\n[+] Original UTF-8 Secret:\n    '{original_secret}'")

    # Convert to Integer
    secret_integer = string_to_int(original_secret)
    print(f"\n[+] Converted Large Integer (Base 10):\n    {secret_integer}")
    print(f"    Bit length: {secret_integer.bit_length()} bits")

    # Check compatibility with the GF(2^521 - 1) prime field from Shamir's Secret Sharing
    PRIME_521 = 2**521 - 1
    if secret_integer < PRIME_521:
        print(f"    [Status] Secure: Integer fits directly within GF(2^521 - 1) prime field!")
    else:
        print(f"    [Status] Warning: Integer exceeds 521 bits. Requires chunking or a larger prime.")

    # Reconstruct back to String
    reconstructed_secret = int_to_string(secret_integer)
    print(f"\n[+] Reconstructed UTF-8 Secret:\n    '{reconstructed_secret}'")

    # Validation Verification
    assert original_secret == reconstructed_secret, "Mismatch detected during conversion!"
    print("\n[OK] Lossless conversion verified successfully!")

    # Test Case 2: Multi-line string test
    multiline_secret = "Line 1: Access Granted\nLine 2: System Secure"
    assert int_to_string(string_to_int(multiline_secret)) == multiline_secret
    print("[OK] Multi-line string lossless conversion verified successfully!")

    print("\n" + "=" * 70)
