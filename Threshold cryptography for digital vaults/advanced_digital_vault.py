"""
Advanced Digital Vault Implementation — Hybrid Encryption Edition

Integrates:
1. AES-256-GCM symmetric encryption for securing arbitrarily large data payloads.
2. Shamir's Secret Sharing (SSS) for threshold-based key distribution.
3. Feldman Verifiable Secret Sharing (VSS) for cryptographically unforgeable share verification.
4. String-to-integer conversion for seamless data encoding.

Architecture:
    - The vault encrypts the user's secret data using a randomly generated AES-256 key.
    - The AES key (256 bits = 32 bytes) is then split into threshold shares using SSS.
    - Feldman VSS commitments are generated so any shareholder can verify their share.
    - To unlock the vault, at least 'threshold' valid shares must be combined to
      reconstruct the AES key, which then decrypts the original data.

This hybrid approach allows the vault to secure data of ANY size (files, documents,
long text) while maintaining information-theoretic security for the key distribution.
"""

import base64
import json
import os
import secrets as secrets_module

from cryptography.hazmat.primitives.ciphers.aead import AESGCM

from shamir_secret_sharing import (
    FELDMAN_G,
    FELDMAN_P,
    FELDMAN_Q,
    PRIME,
    SecurityAlert,
    feldman_verify_share,
    recover_secret,
    recover_secret_feldman,
    split_secret,
    split_secret_feldman,
)
from vault_converter import int_to_string, string_to_int


# Default vault storage file
VAULT_FILE = "vault_data.json"


class AdvancedDigitalVault:
    """
    The original digital vault providing verifiable, information-theoretically
    secure secret storage and retrieval over a Finite Field GF(P).

    Limitation: Can only store strings up to ~65 characters (bounded by 521-bit prime).
    For larger data, use HybridDigitalVault instead.
    """

    def __init__(self, prime: int = PRIME):
        """
        Initializes the vault over the finite field GF(prime).
        
        Mathematical Significance:
        The choice of a sufficiently large prime (e.g., Mersenne Prime 2^521 - 1) ensures
        that the field size is vastly greater than any encoded integer representation of a standard
        secret string, preventing modular overflow and preserving perfect secrecy.

        Args:
            prime: The large prime number establishing the finite field boundaries.
        """
        self.prime = prime

    def create_vault_shares(
        self, secret_text: str, total_shares: int, threshold: int
    ) -> list[tuple[int, int, str]]:
        """
        Encodes a UTF-8 secret string into a large integer and splits it into distinct shares
        using a (threshold, total_shares) threshold scheme over the finite field.

        Args:
            secret_text: The string data to secure within the vault.
            total_shares: Total number of distinct shares (n) to distribute.
            threshold: Minimum number of shares (t) required for successful reconstruction.

        Returns:
            A list of tuples representing verifiable shares: (x, y, verification_hash).
        """
        if threshold < 1:
            raise ValueError("Threshold must be at least 1.")
        if total_shares < threshold:
            raise ValueError(
                "Total shares cannot be less than the required threshold."
            )

        # Step 1: Convert UTF-8 text into a large integer representation
        secret_int = string_to_int(secret_text)

        # Step 2: Validate that the integer fits strictly inside the Finite Field GF(prime)
        if secret_int >= self.prime:
            raise ValueError(
                f"Secret text is too large to be represented within the GF({self.prime}) field. "
                "Consider using a larger prime or chunking the input data."
            )

        # Step 3: Split the integer secret into verifiable shares
        vault_shares = split_secret(secret_int, threshold, total_shares, self.prime)

        return vault_shares

    def open_vault(self, provided_shares: list[tuple[int, int, str]]) -> str:
        """
        Reconstructs and decodes the original secret string from a provided set of shares.

        Args:
            provided_shares: A list of candidate share tuples (x, y, verification_hash).

        Returns:
            The original decoded UTF-8 secret text.

        Raises:
            SecurityAlert: If any share fails its SHA-256 digital fingerprint check.
        """
        if not provided_shares:
            raise ValueError("No shares provided to open the vault.")

        # Step 1: Recover the secret integer via verified Lagrange Interpolation
        recovered_int = recover_secret(provided_shares, self.prime)

        # Step 2: Convert the recovered large integer back into the original UTF-8 text
        original_text = int_to_string(recovered_int)

        return original_text


class HybridDigitalVault:
    """
    Enterprise-grade Hybrid Digital Vault combining:
    - AES-256-GCM: Authenticated symmetric encryption for data of ANY size.
    - Feldman VSS: Cryptographically unforgeable threshold key distribution.

    Architecture:
        1. A random 256-bit AES key is generated to encrypt the user's data.
        2. The AES key is split into shares using Shamir's Secret Sharing.
        3. Feldman commitments are computed for mathematical share verification.
        4. The encrypted data (ciphertext + nonce) is stored as the vault.
        5. Shares are distributed to authorized participants.
        6. To unlock: combine threshold shares → reconstruct AES key → decrypt data.

    This is how real-world systems like cryptocurrency wallets and banking HSMs operate.
    """

    def __init__(self):
        """Initializes the hybrid vault with Feldman VSS parameters."""
        self.feldman_q = FELDMAN_Q
        self.feldman_g = FELDMAN_G
        self.feldman_p = FELDMAN_P

    def create_vault(
        self, secret_data: str, total_shares: int, threshold: int
    ) -> dict:
        """
        Creates an encrypted vault and distributes threshold key shares.

        Process:
            1. Generate a random 256-bit AES key.
            2. Encrypt the secret data using AES-256-GCM (authenticated encryption).
            3. Split the AES key into shares using Feldman VSS.
            4. Return the vault state and individual share data.

        Args:
            secret_data: The secret text/data to secure (can be any length).
            total_shares: Total number of key shares to generate (n).
            threshold: Minimum shares required to unlock the vault (t).

        Returns:
            A dictionary containing:
            - 'vault': The encrypted vault data (nonce, ciphertext, commitments, threshold).
            - 'shares': List of individual share dictionaries for distribution.
        """
        if threshold < 1:
            raise ValueError("Threshold must be at least 1.")
        if total_shares < threshold:
            raise ValueError("Total shares cannot be less than threshold.")
        if not secret_data:
            raise ValueError("Secret data cannot be empty.")

        # Step 1: Generate a cryptographically secure random 256-bit AES key
        aes_key = secrets_module.token_bytes(32)  # 32 bytes = 256 bits
        aes_key_int = int.from_bytes(aes_key, byteorder="big")

        # Step 2: Encrypt the data using AES-256-GCM (provides confidentiality + integrity)
        aesgcm = AESGCM(aes_key)
        nonce = secrets_module.token_bytes(12)  # 96-bit nonce for GCM
        ciphertext = aesgcm.encrypt(nonce, secret_data.encode("utf-8"), None)

        # Step 3: Split the AES key using Feldman VSS
        shares, commitments = split_secret_feldman(
            aes_key_int, threshold, total_shares, self.feldman_q, self.feldman_g, self.feldman_p
        )

        # Step 4: Prepare the vault data structure
        vault_data = {
            "nonce": base64.b64encode(nonce).decode("ascii"),
            "ciphertext": base64.b64encode(ciphertext).decode("ascii"),
            "commitments": [str(c) for c in commitments],
            "threshold": threshold,
            "total_shares": total_shares,
        }

        # Step 5: Prepare individual share packages for distribution
        share_packages = []
        for x, y in shares:
            share_package = {
                "share_id": x,
                "x": x,
                "y": str(y),  # Store as string due to large integer size
                "threshold": threshold,
            }
            share_packages.append(share_package)

        return {"vault": vault_data, "shares": share_packages}

    def open_vault(self, vault_data: dict, provided_shares: list[dict]) -> str:
        """
        Reconstructs the AES key from provided shares and decrypts the vault.

        Process:
            1. Parse and validate the provided shares.
            2. Verify each share against Feldman VSS commitments (unforgeable check).
            3. Reconstruct the AES-256 key using Lagrange Interpolation.
            4. Decrypt the vault contents using AES-256-GCM.

        Args:
            vault_data: The encrypted vault dictionary (nonce, ciphertext, commitments).
            provided_shares: List of share dictionaries provided by participants.

        Returns:
            The decrypted original secret text.

        Raises:
            SecurityAlert: If any share fails Feldman VSS verification.
            ValueError: If decryption fails (wrong key reconstructed).
        """
        if not provided_shares:
            raise ValueError("No shares provided.")

        # Parse vault data
        nonce = base64.b64decode(vault_data["nonce"])
        ciphertext = base64.b64decode(vault_data["ciphertext"])
        commitments = [int(c) for c in vault_data["commitments"]]

        # Parse shares
        shares = [(s["x"], int(s["y"])) for s in provided_shares]

        # Recover AES key using Feldman-verified Lagrange Interpolation
        aes_key_int = recover_secret_feldman(
            shares, commitments, self.feldman_q, self.feldman_g, self.feldman_p, self.feldman_q
        )

        # Convert the integer back to 32 bytes (AES-256 key)
        aes_key = aes_key_int.to_bytes(32, byteorder="big")

        # Decrypt the vault contents
        try:
            aesgcm = AESGCM(aes_key)
            decrypted_data = aesgcm.decrypt(nonce, ciphertext, None)
            return decrypted_data.decode("utf-8")
        except Exception as e:
            raise ValueError(
                "Decryption FAILED. The reconstructed AES key is incorrect. "
                "This typically means insufficient or wrong shares were provided."
            ) from e

    def save_vault_to_file(self, vault_data: dict, filepath: str = VAULT_FILE) -> None:
        """Saves the encrypted vault data to a JSON file."""
        with open(filepath, "w") as f:
            json.dump(vault_data, f, indent=2)

    def load_vault_from_file(self, filepath: str = VAULT_FILE) -> dict:
        """Loads encrypted vault data from a JSON file."""
        with open(filepath, "r") as f:
            return json.load(f)

    def save_shares_to_files(self, shares: list[dict], output_dir: str = "shares") -> list[str]:
        """Saves each share to an individual JSON file for secure distribution."""
        os.makedirs(output_dir, exist_ok=True)
        filepaths = []
        for share in shares:
            filepath = os.path.join(output_dir, f"share_director_{share['share_id']}.json")
            with open(filepath, "w") as f:
                json.dump(share, f, indent=2)
            filepaths.append(filepath)
        return filepaths


# ============================================================
# INTERACTIVE TERMINAL INTERFACE
# ============================================================
if __name__ == "__main__":
    print("=" * 70)
    print("  THRESHOLD CRYPTOGRAPHY FOR DIGITAL VAULTS")
    print("  Hybrid AES-256-GCM + Feldman VSS Edition")
    print("=" * 70)
    print("\nSelect Mode:")
    print("  1. BASIC MODE   — Original SSS (small secrets, SHA-256 checksums)")
    print("  2. HYBRID MODE  — AES-256 + Feldman VSS (any size, unforgeable)")
    
    mode = input("\nEnter mode (1 or 2): ").strip()

    if mode == "1":
        # ---- BASIC MODE (Original Behavior) ----
        vault = AdvancedDigitalVault()

        print("\n--- PHASE 1: Vault Creation ---")
        secret_message = input("Enter the secret message to store in the vault:\n> ").strip()
        
        if not secret_message:
            secret_message = "Default Secret: Digital Vault Initialized"
            print(f"Empty input detected. Using default message: '{secret_message}'")

        try:
            total_n = int(input("\nEnter the total number of shares to generate (n):\n> ").strip())
            threshold_t = int(input("Enter the threshold of shares required to unlock (t):\n> ").strip())
        except ValueError:
            print("\nInvalid integer input. Defaulting to a (3, 5) threshold scheme.")
            total_n = 5
            threshold_t = 3

        print(f"\n[+] Securing secret using a ({threshold_t}, {total_n}) Threshold Scheme...")
        try:
            shares = vault.create_vault_shares(secret_message, total_n, threshold_t)
        except Exception as e:
            print(f"\n[!] Error creating vault shares: {e}")
            exit(1)

        print("\n[+] Successfully Generated Distributed Vault Shares:")
        print("Save these details carefully for the recovery phase below.\n")
        for idx, (x_val, y_val, v_hash) in enumerate(shares, 1):
            print(f"--- Share #{idx} ---")
            print(f"x    = {x_val}")
            print(f"y    = {y_val}")
            print(f"hash = {v_hash}\n")

        # Recovery Phase
        print("=" * 70)
        print("--- PHASE 2: Vault Recovery ---")
        print(f"To unlock the vault, you must provide exactly {threshold_t} valid shares.")
        print("=" * 70)

        provided_shares = []
        for i in range(1, threshold_t + 1):
            print(f"\nInputting details for Share #{i} of {threshold_t}:")
            try:
                share_x = int(input("  Enter x value : ").strip())
                share_y = int(input("  Enter y value : ").strip())
                share_hash = input("  Enter hash    : ").strip()
                provided_shares.append((share_x, share_y, share_hash))
            except ValueError:
                print("\n[!] Invalid input format. Vault opening sequence aborted.")
                exit(1)

        print("\n[+] Attempting to unlock the vault with the provided shares...")
        try:
            unlocked_secret = vault.open_vault(provided_shares)
            print("\n" + "*" * 70)
            print("  [SUCCESS] VAULT UNLOCKED!")
            print(f"  Recovered Secret Message:\n  '{unlocked_secret}'")
            print("*" * 70)
        except SecurityAlert as alert:
            print("\n" + "!" * 70)
            print("  [SECURITY ALERT] VAULT ACCESS DENIED!")
            print(f"  Reason: {alert}")
            print("!" * 70)
        except Exception as err:
            print(f"\n[!] Failed to open vault: {err}")

    elif mode == "2":
        # ---- HYBRID MODE (AES-256 + Feldman VSS) ----
        vault = HybridDigitalVault()

        print("\nSelect Action:")
        print("  1. CREATE a new encrypted vault (lock data & distribute keys)")
        print("  2. OPEN an existing vault (combine keys to unlock)")
        action = input("\nEnter action (1 or 2): ").strip()

        if action == "1":
            print("\n--- VAULT CREATION (AES-256-GCM + Feldman VSS) ---")
            secret_data = input("Enter the secret data to secure (any length):\n> ").strip()

            if not secret_data:
                secret_data = "Default Vault Secret: Threshold Cryptography Demo"
                print(f"Using default: '{secret_data}'")

            try:
                total_n = int(input("\nTotal number of key shares to generate (n):\n> ").strip())
                threshold_t = int(input("Threshold of shares needed to unlock (t):\n> ").strip())
            except ValueError:
                print("Invalid input. Defaulting to (3, 5).")
                total_n = 5
                threshold_t = 3

            print(f"\n[+] Creating vault with ({threshold_t}, {total_n}) threshold scheme...")
            result = vault.create_vault(secret_data, total_n, threshold_t)

            # Save vault data
            vault.save_vault_to_file(result["vault"])
            print(f"[+] Encrypted vault saved to: {VAULT_FILE}")

            # Save shares to individual files
            share_files = vault.save_shares_to_files(result["shares"])
            print(f"[+] {len(share_files)} key share files saved to 'shares/' directory:")
            for sf in share_files:
                print(f"    -> {sf}")

            print(f"\n[+] Feldman VSS Commitments (public):")
            for idx, c in enumerate(result["vault"]["commitments"]):
                print(f"    C_{idx} = {c[:60]}...")

            print("\n" + "*" * 70)
            print("  VAULT CREATED SUCCESSFULLY!")
            print(f"  Distribute the share files to {total_n} authorized directors.")
            print(f"  At least {threshold_t} directors must combine keys to unlock.")
            print("*" * 70)

        elif action == "2":
            print("\n--- VAULT RECOVERY (AES-256-GCM + Feldman VSS) ---")

            # Load vault data
            vault_path = input(f"Enter vault file path (default: {VAULT_FILE}):\n> ").strip()
            if not vault_path:
                vault_path = VAULT_FILE

            try:
                vault_data = vault.load_vault_from_file(vault_path)
            except FileNotFoundError:
                print(f"[!] Vault file '{vault_path}' not found.")
                exit(1)

            threshold_t = vault_data.get("threshold", 3)
            print(f"[+] Vault loaded. Requires {threshold_t} shares to unlock.\n")

            # Collect shares
            provided_shares = []
            num_shares = int(input(f"How many share files are you providing? (min {threshold_t}):\n> ").strip())

            for i in range(1, num_shares + 1):
                share_path = input(f"  Path to share file #{i}: ").strip()
                try:
                    with open(share_path, "r") as f:
                        share = json.load(f)
                    provided_shares.append(share)
                    print(f"    ✓ Loaded share from Director #{share['share_id']}")
                except Exception as e:
                    print(f"    ✗ Error loading share: {e}")
                    exit(1)

            print("\n[+] Attempting to unlock vault with provided shares...")
            try:
                decrypted = vault.open_vault(vault_data, provided_shares)
                print("\n" + "*" * 70)
                print("  [SUCCESS] VAULT UNLOCKED!")
                print(f"  Decrypted Data:\n  '{decrypted}'")
                print("*" * 70)
            except SecurityAlert as alert:
                print("\n" + "!" * 70)
                print("  [SECURITY ALERT] VAULT ACCESS DENIED!")
                print(f"  Feldman VSS Verification Failed: {alert}")
                print("!" * 70)
            except ValueError as err:
                print(f"\n[!] {err}")

    else:
        print("Invalid selection. Please run again and choose 1 or 2.")

    print("\n" + "=" * 70)
