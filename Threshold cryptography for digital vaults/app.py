"""
Flask Web Application for Threshold Cryptography Digital Vault

Provides a beautiful web dashboard for:
- Creating encrypted vaults with AES-256-GCM + Feldman VSS
- Downloading individual key share files for distribution
- Uploading key shares to unlock and decrypt the vault
- Real-time Feldman VSS commitment verification
"""

import json
import os

from flask import Flask, jsonify, render_template, request

from advanced_digital_vault import HybridDigitalVault

app = Flask(__name__)
vault_engine = HybridDigitalVault()

# In-memory vault storage (for the web session)
current_vault = None


@app.route("/")
def index():
    """Serves the main web dashboard."""
    return render_template("index.html")


@app.route("/api/create-vault", methods=["POST"])
def create_vault():
    """
    API endpoint to create a new encrypted vault.

    Expects JSON body:
    {
        "secret_data": "the secret text to secure",
        "total_shares": 5,
        "threshold": 3
    }

    Returns JSON with vault data and individual share packages.
    """
    global current_vault

    try:
        data = request.get_json()
        secret_data = data.get("secret_data", "").strip()
        total_shares = int(data.get("total_shares", 5))
        threshold = int(data.get("threshold", 3))

        if not secret_data:
            return jsonify({"error": "Secret data cannot be empty."}), 400
        if threshold < 1:
            return jsonify({"error": "Threshold must be at least 1."}), 400
        if total_shares < threshold:
            return jsonify({"error": "Total shares must be >= threshold."}), 400

        # Create the vault
        result = vault_engine.create_vault(secret_data, total_shares, threshold)

        # Store vault data for later recovery
        current_vault = result["vault"]

        # Also save to disk
        vault_engine.save_vault_to_file(result["vault"])

        return jsonify({
            "success": True,
            "vault": result["vault"],
            "shares": result["shares"],
            "message": f"Vault created with ({threshold}, {total_shares}) threshold scheme."
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


@app.route("/api/open-vault", methods=["POST"])
def open_vault():
    """
    API endpoint to open/decrypt a vault using provided shares.

    Expects JSON body:
    {
        "shares": [
            {"share_id": 1, "x": 1, "y": "..."},
            {"share_id": 3, "x": 3, "y": "..."},
            ...
        ],
        "vault": { ... }  // optional, uses stored vault if not provided
    }

    Returns the decrypted secret data.
    """
    global current_vault

    try:
        data = request.get_json()
        provided_shares = data.get("shares", [])
        vault_data = data.get("vault", current_vault)

        if not vault_data:
            # Try loading from file
            try:
                vault_data = vault_engine.load_vault_from_file()
            except FileNotFoundError:
                return jsonify({"error": "No vault found. Create a vault first."}), 404

        if not provided_shares:
            return jsonify({"error": "No shares provided."}), 400

        # Attempt to open the vault
        decrypted = vault_engine.open_vault(vault_data, provided_shares)

        return jsonify({
            "success": True,
            "decrypted_data": decrypted,
            "shares_used": len(provided_shares),
            "message": "Vault unlocked successfully!"
        })

    except Exception as e:
        error_type = type(e).__name__
        return jsonify({
            "error": str(e),
            "error_type": error_type
        }), 400


@app.route("/api/verify-share", methods=["POST"])
def verify_share():
    """
    API endpoint to verify a single share against Feldman VSS commitments.

    Expects JSON body:
    {
        "x": 1,
        "y": "...",
        "commitments": ["...", "...", ...]
    }
    """
    try:
        from shamir_secret_sharing import feldman_verify_share

        data = request.get_json()
        x = int(data["x"])
        y = int(data["y"])
        commitments = [int(c) for c in data["commitments"]]

        is_valid = feldman_verify_share(x, y, commitments)

        return jsonify({
            "valid": is_valid,
            "share_id": x,
            "message": "Share is VALID" if is_valid else "Share FAILED verification"
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


if __name__ == "__main__":
    print("\n" + "=" * 60)
    print("  THRESHOLD CRYPTOGRAPHY DIGITAL VAULT — Web Dashboard")
    print("  Open http://127.0.0.1:5000 in your browser")
    print("=" * 60 + "\n")
    app.run(debug=True, port=5000)
