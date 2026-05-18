import hashlib
import secrets

# ============================================================
# FINITE FIELD DEFINITION
# ============================================================
# Mersenne Prime 2^521 - 1 for the basic SSS field
PRIME = 2**521 - 1

# ============================================================
# FELDMAN VSS PARAMETERS (RFC 3526, Group 14 - 2048-bit MODP)
# ============================================================
# Safe prime p from RFC 3526 where q = (p-1)/2 is also prime.
# This provides a group where the Discrete Logarithm Problem is hard,
# enabling cryptographically binding commitments for Verifiable Secret Sharing.
FELDMAN_P = int(
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1"
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD"
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245"
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED"
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D"
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F"
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D6"
    "70C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE"
    "39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9D"
    "E2BCBF6955817183995497CEA956AE515D2261898FA05101"
    "5728E5A8AACAA68FFFFFFFFFFFFFFFF", 16
)

# Generator of the subgroup of prime order q in Z_p*
# Using g = 4 (i.e., 2^2) ensures the generator has order q = (p-1)/2 (prime order),
# which is required for the security proof of Feldman VSS.
FELDMAN_G = pow(2, 2, FELDMAN_P)

# Prime-order subgroup: q = (p - 1) / 2
FELDMAN_Q = (FELDMAN_P - 1) // 2


# ============================================================
# CORE FINITE FIELD ARITHMETIC
# ============================================================

def extended_gcd(a: int, b: int) -> tuple[int, int, int]:
    """
    Computes the greatest common divisor of a and b, along with the coefficients
    x and y such that: a*x + b*y = gcd(a, b) using the Extended Euclidean Algorithm.
    """
    x0, x1, y0, y1 = 1, 0, 0, 1
    while b != 0:
        q, a, b = a // b, b, a % b
        x0, x1 = x1, x0 - q * x1
        y0, y1 = y1, y0 - q * y1
    return a, x0, y0


def mod_inverse(k: int, prime: int = PRIME) -> int:
    """
    Calculates the Modular Multiplicative Inverse of k modulo prime.
    
    Returns an integer x such that (k * x) % prime == 1.
    Essential for cryptographic division within the finite field.
    """
    k = k % prime
    if k == 0:
        raise ZeroDivisionError("Division by zero: modular inverse of zero does not exist.")
    
    gcd, x, _ = extended_gcd(k, prime)
    if gcd != 1:
        raise ValueError(f"Modular inverse does not exist for {k} mod {prime}.")
    
    return x % prime


# ============================================================
# POLYNOMIAL OPERATIONS
# ============================================================

def generate_polynomial(secret: int, t: int, prime: int = PRIME) -> list[int]:
    """
    Generates a random polynomial of degree t - 1 over the finite field GF(prime),
    where the constant term (a_0) is the secret.

    f(x) = a_0 + a_1*x + a_2*x^2 + ... + a_{t-1}*x^{t-1}

    Args:
        secret: The secret integer to be shared (must be in range [0, prime - 1]).
        t: The threshold number of shares required to reconstruct the secret.
        prime: The prime number defining the finite field.

    Returns:
        A list of t coefficients [a_0, a_1, ..., a_{t-1}].
    """
    if not (0 <= secret < prime):
        raise ValueError("The secret must be within the finite field [0, prime - 1].")
    if t < 1:
        raise ValueError("Threshold t must be at least 1.")

    # a_0 is the secret
    coefficients = [secret]

    # Generate random coefficients a_1, ..., a_{t-1} using cryptographically secure RNG
    for _ in range(1, t):
        coefficients.append(secrets.randbelow(prime))

    return coefficients


def evaluate_polynomial(coefficients: list[int], x: int, prime: int = PRIME) -> int:
    """
    Evaluates the polynomial at a given point x using Horner's method modulo prime.
    
    Args:
        coefficients: List of coefficients [a_0, a_1, ..., a_{t-1}].
        x: The x-coordinate (share index).
        prime: The prime defining the finite field.
        
    Returns:
        The y-coordinate (share value) f(x) mod prime.
    """
    result = 0
    # Horner's method ensures efficient polynomial evaluation
    for coeff in reversed(coefficients):
        result = (result * x + coeff) % prime
    return result


# ============================================================
# BASIC SECRET SHARING (with SHA-256 checksums)
# ============================================================

def split_secret(secret: int, t: int, n: int, prime: int = PRIME) -> list[tuple[int, int, str]]:
    """
    Splits a secret integer into n distinct shares using a (t, n) threshold scheme,
    incorporating a SHA-256 hash for each y-value as a basic integrity check.

    Args:
        secret: The secret integer to be shared.
        t: The threshold number of shares required to reconstruct the secret.
        n: The total number of shares to generate.
        prime: The prime defining the finite field.

    Returns:
        A list of n tuples, each formatted as:
        (x, y, verification_hash)
    """
    if n < t:
        raise ValueError("Total number of shares n cannot be less than threshold t.")

    # Generate the underlying polynomial of degree t - 1
    poly = generate_polynomial(secret, t, prime)

    shares = []
    for x in range(1, n + 1):
        y = evaluate_polynomial(poly, x, prime)
        
        # Compute SHA-256 digital fingerprint of the share's y-value
        y_bytes = str(y).encode("utf-8")
        verification_hash = hashlib.sha256(y_bytes).hexdigest()
        
        shares.append((x, y, verification_hash))

    return shares


class SecurityAlert(Exception):
    """Custom exception raised when share tampering or signature verification mismatch is detected."""
    pass


def recover_secret(shares: list[tuple[int, int, str]], prime: int = PRIME) -> int:
    """
    Reconstructs the original secret using Lagrange Interpolation over the finite field GF(prime).

    Accepts a list of t or more shares, verifies each one against its stored SHA-256 fingerprint,
    and performs modular fractional arithmetic to derive the constant term f(0).

    Args:
        shares: List of tuples (x, y, verification_hash).
        prime: The prime defining the finite field.

    Returns:
        The reconstructed original secret integer.

    Raises:
        SecurityAlert: If any share's SHA-256 hash fails verification.
    """
    # Step 1: Verify each share against its stored SHA-256 hash
    for x, y, v_hash in shares:
        y_bytes = str(y).encode("utf-8")
        computed_hash = hashlib.sha256(y_bytes).hexdigest()
        if computed_hash != v_hash:
            raise SecurityAlert("Security Alert: Tampering Detected")

    # Step 2: Reconstruct secret using Lagrange Interpolation at x = 0
    secret = 0
    for i, (x_i, y_i, _) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (x_j, _, _) in enumerate(shares):
            if i != j:
                # numerator = product(0 - x_j) mod prime
                numerator = (numerator * (-x_j)) % prime
                # denominator = product(x_i - x_j) mod prime
                denominator = (denominator * (x_i - x_j)) % prime

        # Utilize modular inverse logic for fractional division
        inv_denom = mod_inverse(denominator, prime)

        # Compute the Lagrange basis polynomial value at x = 0
        lagrange_basis = (numerator * inv_denom) % prime

        # Accumulate the term contribution
        secret = (secret + y_i * lagrange_basis) % prime

    return secret


# ============================================================
# FELDMAN VERIFIABLE SECRET SHARING (VSS)
# ============================================================
# Unlike the basic SHA-256 checksums above, Feldman VSS provides
# cryptographic, mathematically unforgeable share verification.
# A malicious shareholder CANNOT create a fake share that passes
# Feldman verification without solving the Discrete Logarithm Problem.
# ============================================================

def feldman_generate_commitments(
    coefficients: list[int],
    g: int = FELDMAN_G,
    p: int = FELDMAN_P
) -> list[int]:
    """
    Generates Feldman VSS commitments for each polynomial coefficient.

    Commitment: C_j = g^{a_j} mod p

    These commitments are broadcast publicly by the dealer and allow any
    shareholder to verify their share without revealing the polynomial or the secret.

    Args:
        coefficients: The polynomial coefficients [a_0, a_1, ..., a_{t-1}].
        g: Generator of the prime-order subgroup in Z_p*.
        p: The safe prime defining the group.

    Returns:
        A list of commitments [C_0, C_1, ..., C_{t-1}].
    """
    return [pow(g, coeff, p) for coeff in coefficients]


def feldman_verify_share(
    x: int,
    y: int,
    commitments: list[int],
    g: int = FELDMAN_G,
    p: int = FELDMAN_P,
    q: int = FELDMAN_Q
) -> bool:
    """
    Verifies a share (x, y) against the public Feldman commitments.

    Checks the equation: g^y mod p == Product(C_j^{x^j}) mod p

    Mathematical Proof:
        g^{f(x)} = g^{a_0 + a_1*x + a_2*x^2 + ...}
                  = g^{a_0} * g^{a_1*x} * g^{a_2*x^2} * ...
                  = C_0^1 * C_1^x * C_2^{x^2} * ...
                  = Product(C_j^{x^j})

    Security: Forging a share that passes this check requires computing
    discrete logarithms, which is computationally infeasible in this group.

    Args:
        x: The share's x-coordinate (shareholder index).
        y: The share's y-coordinate (polynomial evaluation).
        commitments: The public Feldman commitments [C_0, ..., C_{t-1}].
        g: Generator of the prime-order subgroup.
        p: The safe prime defining the group.
        q: The prime order of the subgroup (for exponent reduction).

    Returns:
        True if the share is valid, False if it has been tampered with.
    """
    # Left-hand side: g^y mod p
    lhs = pow(g, y % q, p)

    # Right-hand side: Product of C_j^{x^j} mod p
    rhs = 1
    x_power = 1  # x^0 = 1
    for commitment in commitments:
        rhs = (rhs * pow(commitment, x_power, p)) % p
        x_power = (x_power * x)

    return lhs == rhs


def split_secret_feldman(
    secret: int,
    t: int,
    n: int,
    prime: int = FELDMAN_Q,
    g: int = FELDMAN_G,
    p: int = FELDMAN_P
) -> tuple[list[tuple[int, int]], list[int]]:
    """
    Splits a secret using Shamir's Secret Sharing with Feldman VSS commitments.

    This is the cryptographically superior version of split_secret(). Instead of
    using forgeable SHA-256 hashes, it generates mathematical commitments based
    on the Discrete Logarithm Problem.

    Args:
        secret: The secret integer to be shared (must be < prime).
        t: Threshold of shares needed to reconstruct.
        n: Total number of shares to generate.
        prime: The prime order of the subgroup (field for polynomial arithmetic).
        g: Generator of the prime-order subgroup.
        p: The safe prime defining the group.

    Returns:
        A tuple of (shares, commitments):
        - shares: list of (x, y) tuples
        - commitments: list of C_j = g^{a_j} mod p values
    """
    if n < t:
        raise ValueError("Total shares n cannot be less than threshold t.")
    if not (0 <= secret < prime):
        raise ValueError(f"Secret must be in range [0, {prime}).")

    # Generate the random polynomial with secret as constant term
    poly = generate_polynomial(secret, t, prime)

    # Generate Feldman commitments (publicly broadcastable)
    commitments = feldman_generate_commitments(poly, g, p)

    # Evaluate the polynomial at x = 1, 2, ..., n to create shares
    shares = []
    for x in range(1, n + 1):
        y = evaluate_polynomial(poly, x, prime)
        shares.append((x, y))

    return shares, commitments


def recover_secret_feldman(
    shares: list[tuple[int, int]],
    commitments: list[int],
    prime: int = FELDMAN_Q,
    g: int = FELDMAN_G,
    p: int = FELDMAN_P,
    q: int = FELDMAN_Q
) -> int:
    """
    Recovers the secret from shares after verifying each with Feldman VSS commitments.

    Unlike recover_secret(), this function uses mathematically unforgeable verification.
    A malicious shareholder CANNOT create a fake share that passes this check.

    Args:
        shares: List of (x, y) tuples.
        commitments: The public Feldman commitments.
        prime: The prime field for polynomial arithmetic.
        g: Generator of the prime-order subgroup.
        p: The safe prime defining the group.
        q: The prime order of the subgroup.

    Returns:
        The reconstructed secret integer.

    Raises:
        SecurityAlert: If any share fails Feldman verification (tampered or invalid).
    """
    # Step 1: Verify each share against Feldman commitments
    for x, y in shares:
        if not feldman_verify_share(x, y, commitments, g, p, q):
            raise SecurityAlert(
                f"FELDMAN VSS ALERT: Share x={x} FAILED cryptographic verification. "
                "This share has been tampered with or is invalid. "
                "Unlike SHA-256 checksums, this verification is mathematically unforgeable."
            )

    # Step 2: Lagrange Interpolation at x = 0 to reconstruct secret
    secret = 0
    for i, (x_i, y_i) in enumerate(shares):
        numerator = 1
        denominator = 1
        for j, (x_j, _) in enumerate(shares):
            if i != j:
                numerator = (numerator * (-x_j)) % prime
                denominator = (denominator * (x_i - x_j)) % prime

        inv_denom = mod_inverse(denominator, prime)
        lagrange_basis = (numerator * inv_denom) % prime
        secret = (secret + y_i * lagrange_basis) % prime

    return secret


# ============================================================
# STANDALONE DEMONSTRATION
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("Shamir's Secret Sharing - Full Suite Demonstration (VSS + Recovery)")
    print("=" * 70)

    # 1. Finite Field setup
    print(f"\n[+] Finite Field defined by Mersenne Prime 2^521 - 1:")
    print(f"    P = {PRIME}")
    print(f"    Bit length: {PRIME.bit_length()} bits")

    # 2. Modular Multiplicative Inverse demonstration
    k = 123456789
    inv = mod_inverse(k, PRIME)
    print(f"\n[+] Modular Multiplicative Inverse Test:")
    print(f"    k       = {k}")
    print(f"    inv(k)  = {inv}")
    print(f"    Check   = (k * inv(k)) % PRIME = {(k * inv) % PRIME}")
    assert (k * inv) % PRIME == 1

    # 3. Basic Verifiable Secret Sharing (SHA-256) Splitting
    my_secret = 999888777666  # Core secret integer
    threshold = 3             # t = 3 shares needed to reconstruct
    num_shares = 5            # n = 5 total shares generated

    print(f"\n[+] Splitting Secret using ({threshold}, {num_shares}) Threshold Scheme with VSS:")
    print(f"    Secret Integer = {my_secret}")

    vss_shares = split_secret(my_secret, threshold, num_shares, PRIME)

    print("\n[+] Generated Shares with SHA-256 Digital Fingerprints:")
    for x, y, v_hash in vss_shares:
        print(f"\n    Share x = {x}")
        print(f"    Share y = {y}")
        print(f"    SHA-256 = {v_hash}")

    # 4. Secret Recovery Demonstration
    print(f"\n[+] Attempting Secret Recovery using exactly {threshold} shares (Shares 1, 3, and 5):")
    subset_shares = [vss_shares[0], vss_shares[2], vss_shares[4]]
    recovered_secret = recover_secret(subset_shares, PRIME)
    
    print(f"    Reconstructed Secret = {recovered_secret}")
    assert recovered_secret == my_secret
    print("    [OK] Secret reconstructed successfully and matches original!")

    # 5. Tampering Detection Demonstration
    print("\n[+] Testing Tampering Detection Logic:")
    # Tamper with the y-value of the first share while preserving its original verification hash
    tampered_share = (subset_shares[0][0], subset_shares[0][1] + 1, subset_shares[0][2])
    tampered_subset = [tampered_share, subset_shares[1], subset_shares[2]]

    try:
        recover_secret(tampered_subset, PRIME)
    except SecurityAlert as e:
        print(f"    [OK] Successfully intercepted tampered share! Caught Exception:\n         {e.__class__.__name__}: {e}")

    # 6. FELDMAN VSS Demonstration
    print("\n" + "=" * 70)
    print("FELDMAN VERIFIABLE SECRET SHARING (Cryptographically Unforgeable)")
    print("=" * 70)

    print(f"\n[+] Feldman Parameters:")
    print(f"    Safe Prime (p): {FELDMAN_P.bit_length()}-bit (RFC 3526 Group 14)")
    print(f"    Subgroup Order (q): {FELDMAN_Q.bit_length()}-bit")
    print(f"    Generator (g): {FELDMAN_G}")

    feldman_secret = 42424242424242
    f_threshold = 3
    f_num_shares = 5

    print(f"\n[+] Splitting with Feldman VSS ({f_threshold}, {f_num_shares}) scheme:")
    print(f"    Secret = {feldman_secret}")

    f_shares, f_commitments = split_secret_feldman(feldman_secret, f_threshold, f_num_shares)

    print(f"\n[+] Public Commitments (g^a_j mod p) — broadcast to all participants:")
    for idx, c in enumerate(f_commitments):
        print(f"    C_{idx} = {str(c)[:60]}...")

    print(f"\n[+] Verifying all {f_num_shares} shares against commitments:")
    for x, y in f_shares:
        valid = feldman_verify_share(x, y, f_commitments)
        status = "VALID" if valid else "INVALID"
        print(f"    Share x={x}: {status}")

    print(f"\n[+] Recovering secret from shares 1, 3, 5:")
    f_subset = [f_shares[0], f_shares[2], f_shares[4]]
    f_recovered = recover_secret_feldman(f_subset, f_commitments)
    print(f"    Recovered = {f_recovered}")
    assert f_recovered == feldman_secret
    print("    [OK] Feldman VSS recovery successful!")

    # 7. Feldman Tampering Detection
    print(f"\n[+] Testing Feldman tampering detection:")
    tampered_f_share = (f_shares[0][0], f_shares[0][1] + 1)
    tampered_f_subset = [tampered_f_share, f_shares[2], f_shares[4]]

    try:
        recover_secret_feldman(tampered_f_subset, f_commitments)
    except SecurityAlert as e:
        print(f"    [OK] Feldman VSS caught tampered share!\n         {e.__class__.__name__}: {e}")

    print("\n" + "=" * 70)
