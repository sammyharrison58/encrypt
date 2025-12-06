import json
import string
import sys
from typing import Dict, List
import random

CHARSET: List[str] = list(
    string.punctuation + string.digits + string.ascii_letters + " "
)


def generate_key(seed: int | None = None) -> List[str]:
    """
    Generate a shuffled substitution key for the configured CHARSET.

    Args:
        seed: Optional seed for deterministic key generation (useful for tests).

    Returns:
        A list representing the shuffled key mapping aligned with CHARSET.
    """
    rng = random.Random(seed)
    key = CHARSET.copy()
    rng.shuffle(key)
    return key


def build_maps(key: List[str]) -> tuple[Dict[str, str], Dict[str, str]]:
    """
    Build forward (plain->cipher) and reverse (cipher->plain) maps from a key.

    Args:
        key: The shuffled key aligned with CHARSET indices.

    Returns:
        (enc_map, dec_map)
    """
    enc_map = {orig: enc for orig, enc in zip(CHARSET, key)}
    dec_map = {enc: orig for orig, enc in zip(CHARSET, key)}
    return enc_map, dec_map


def encrypt(text: str, key: List[str], passthrough_unknown: bool = True) -> str:
    enc_map, _ = build_maps(key)
    out_chars: List[str] = []
    for ch in text:
        if ch in enc_map:
            out_chars.append(enc_map[ch])
        elif passthrough_unknown:
            out_chars.append(ch)
        else:
            raise ValueError(f"Unsupported character during encryption: {repr(ch)}")
    return "".join(out_chars)


def decrypt(text: str, key: List[str], passthrough_unknown: bool = True) -> str:
    _, dec_map = build_maps(key)
    out_chars: List[str] = []
    for ch in text:
        if ch in dec_map:
            out_chars.append(dec_map[ch])
        elif passthrough_unknown:
            out_chars.append(ch)
        else:
            raise ValueError(f"Unsupported character in decryption: {repr(ch)}")
    return "".join(out_chars)


def serialize_key(key: List[str]) -> str:
    """Serialize key to  JSON string."""
    return json.dumps({"key": key}, separators=(",", ":"))


def deserialize_key(s: str) -> List[str]:
    """Deserialize key from JSON string produced by serialize_key."""
    try:
        data = json.loads(s)
        key = data["key"]
        if not isinstance(key, list) or any(
            not isinstance(c, str) or len(c) != 1 for c in key
        ):
            raise ValueError("Invalid key format")
        if len(key) != len(CHARSET):
            raise ValueError("Key length does not match charset length")
        return key
    except (ValueError, KeyError, json.JSONDecodeError) as exc:
        raise ValueError(f"Failed to  key: {exc}") from exc


def prompt_mode() -> str:
    print("Select mode:")
    print("  1) Encrypt")
    print("  2) Decrypt")
    choice = input("Enter 1 or 2: ").strip()
    if choice == "1":
        return "encrypt"
    if choice == "2":
        return "decrypt"
    raise SystemExit("Invalid selection. Expected 1 or 2.")


def main() -> None:
    try:
        mode = prompt_mode()

        if mode == "encrypt":
            seed_input = input(
                "please press enter key to continue(press Enter to continue): "
            ).strip()
            seed = int(seed_input) if seed_input else None
            key = generate_key(seed)

            plain_text = input("Enter the text to be encrypted: ")
            try:
                cipher_text = encrypt(plain_text, key)
            except ValueError as e:
                print(f"Error: {e}")
                raise SystemExit(1)

            print("--- Result ---")
            print(f"Plaintext: {plain_text}")
            print(f"Ciphertext: {cipher_text}")
            print("Keep this key safe to decrypt:")
            print(serialize_key(key))

        else:  # decrypt
            key_str = input("Paste the key JSON: ").strip()
            try:
                key = deserialize_key(key_str)
            except ValueError as e:
                print(f"Error: {e}")
                raise SystemExit(1)

            cipher_text = input("Enter the text to be decrypted: ")
            try:
                plain_text = decrypt(cipher_text, key)
            except ValueError as e:
                print(f"Error: {e}")
                raise SystemExit(1)

            print("--- Result ---")
            print(f"Ciphertext: {cipher_text}")
            print(f"Plaintext: {plain_text}")

    except KeyboardInterrupt:
        print("\nOperation cancelled.")
        sys.exit(1)


if __name__ == "__main__":
    main()
