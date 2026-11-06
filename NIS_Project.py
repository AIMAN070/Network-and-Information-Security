import time
import random
import string
from math import gcd

# ==================== ENCRYPTION KEYS ====================

VIGENERE_KEY = "NETWORKSAFE"
AFFINE_A = 5
AFFINE_B = 8

KEY_LENGTH = len(VIGENERE_KEY)
ALPHABET_SIZE = 26

# Valid multiplicative keys for Affine cipher:
# gcd(A, 26) must be 1 so that a modular inverse exists.
VALID_A = [a for a in range(1, 26) if gcd(a, 26) == 1]


# ==================== VALIDATION ====================

def validate_keys():
    if len(VIGENERE_KEY) < 10:
        raise ValueError("Vigenere key must contain at least 10 characters.")

    if not VIGENERE_KEY.isascii() or not VIGENERE_KEY.isalpha() or not VIGENERE_KEY.isupper():
        raise ValueError("Vigenere key must contain uppercase A-Z only.")

    if not isinstance(AFFINE_A, int) or gcd(AFFINE_A, 26) != 1:
        raise ValueError("Affine A must be an integer coprime with 26.")

    if not isinstance(AFFINE_B, int) or not 0 <= AFFINE_B < 26:
        raise ValueError("Affine B must be an integer between 0 and 25.")


def valid_text(text):
    return bool(text) and text.isascii() and text.isalpha() and text.isupper()


# ==================== VIGENERE CIPHER ====================

def vigenere_encrypt(text, key):
    return ''.join(
        chr((ord(ch) - 65 + ord(key[i % len(key)]) - 65) % 26 + 65)
        for i, ch in enumerate(text)
    )


def vigenere_decrypt(text, key):
    return ''.join(
        chr((ord(ch) - 65 - (ord(key[i % len(key)]) - 65)) % 26 + 65)
        for i, ch in enumerate(text)
    )


# ==================== PROGRESSIVE AFFINE CIPHER ====================

# C[i] = (A * P[i] + B * (i + 1)) mod 26

def affine_encrypt(text, a, b):
    return ''.join(
        chr((a * (ord(ch) - 65) + b * (i + 1)) % 26 + 65)
        for i, ch in enumerate(text)
    )


def affine_decrypt(text, a, b):
    inverse = pow(a, -1, 26)

    return ''.join(
        chr((inverse * ((ord(ch) - 65) - b * (i + 1))) % 26 + 65)
        for i, ch in enumerate(text)
    )


# ==================== HYBRID CIPHER ====================

def hybrid_encrypt(text):
    stage1 = vigenere_encrypt(text, VIGENERE_KEY)
    return affine_encrypt(stage1, AFFINE_A, AFFINE_B)


def hybrid_decrypt(text):
    stage1 = affine_decrypt(text, AFFINE_A, AFFINE_B)
    return vigenere_decrypt(stage1, VIGENERE_KEY)


def hybrid_encrypt_with_keys(text, key, a, b):
    stage1 = vigenere_encrypt(text, key)
    return affine_encrypt(stage1, a, b)


# ==================== SHIFT CIPHER BASELINE ====================

def shift_encrypt(text, shift=3):
    return ''.join(
        chr((ord(ch) - 65 + shift) % 26 + 65)
        for ch in text
    )


def shift_decrypt(text, shift=3):
    return ''.join(
        chr((ord(ch) - 65 - shift) % 26 + 65)
        for ch in text
    )


# ==================== KNOWN-PLAINTEXT ATTACK ====================

def find_attack_candidates(ciphertext, known_plaintext):
    """
    Recover candidate keys using only a known plaintext prefix and its
    corresponding ciphertext prefix. The complete plaintext is decrypted
    only after a candidate key has been derived and verified.

    Returns:
        candidates, effort
    """
    candidates = []
    character_checks = 0
    full_decryptions = 0

    for a in VALID_A:
        inverse = pow(a, -1, 26)

        for b in range(26):
            key_values = [None] * KEY_LENGTH
            consistent = True

            for i, (p_char, c_char) in enumerate(
                zip(known_plaintext, ciphertext)
            ):
                character_checks += 1
                p = ord(p_char) - 65
                c = ord(c_char) - 65

                # Reverse the Progressive Affine stage.
                vigenere_value = (
                    inverse * (c - b * (i + 1))
                ) % 26

                # Derive the corresponding Vigenere key character.
                key_value = (vigenere_value - p) % 26
                position = i % KEY_LENGTH

                if key_values[position] is None:
                    key_values[position] = key_value
                elif key_values[position] != key_value:
                    consistent = False
                    break

            # Every Vigenere key position must be known and consistent.
            if not consistent or any(value is None for value in key_values):
                continue

            recovered_key = ''.join(
                chr(value + 65) for value in key_values
            )

            # Verify the candidate against the entire known portion.
            test_ciphertext = hybrid_encrypt_with_keys(
                known_plaintext, recovered_key, a, b
            )

            if test_ciphertext == ciphertext[:len(known_plaintext)]:
                # Only now decrypt the complete ciphertext.
                intermediate = affine_decrypt(ciphertext, a, b)
                recovered_plaintext = vigenere_decrypt(
                    intermediate, recovered_key
                )
                full_decryptions += 1

                candidates.append(
                    (recovered_key, a, b, recovered_plaintext)
                )

    # Remove duplicate records without changing their order.
    candidates = list(dict.fromkeys(candidates))

    effort = {
        "key_pairs_tested": len(VALID_A) * 26,
        "character_checks": character_checks,
        "full_decryptions": full_decryptions,
    }
    return candidates, effort


def known_plaintext_attack(ciphertext, known_plaintext):
    """
    The attacker knows a plaintext prefix and its matching ciphertext.
    No original encryption key is supplied to this attack function.
    """
    print("\n" + "-" * 55)
    print("KNOWN-PLAINTEXT ATTACK")
    print("-" * 55)

    print("Known plaintext       :", known_plaintext)
    print("Known length          :", len(known_plaintext))
    print("Assumed key length    :", KEY_LENGTH)
    print("Ciphertext            :", ciphertext)

    if len(known_plaintext) < KEY_LENGTH:
        print("\nAttack Status         : INSUFFICIENT DATA")
        print(
            f"At least {KEY_LENGTH} known characters are required "
            "to derive all Vigenere key positions."
        )
        return

    if len(known_plaintext) > len(ciphertext):
        print("\nAttack Status         : INVALID INPUT")
        print("Known plaintext cannot be longer than the ciphertext.")
        return

    start = time.perf_counter()
    candidates, effort = find_attack_candidates(
        ciphertext, known_plaintext
    )
    elapsed = time.perf_counter() - start

    print("\n" + "-" * 75)
    print("ATTACK RESULTS")
    print("-" * 75)
    print("Key pairs tested      :", effort["key_pairs_tested"])
    print("Character checks      :", effort["character_checks"])
    print("Matching candidates   :", len(candidates))
    print("Full decryptions      :", effort["full_decryptions"])
    print(f"Attack time           : {elapsed:.8f} seconds")

    if len(candidates) == 0:
        print("Attack Status         : NO MATCH")
        print("No consistent key combination was found.")
        print("The known pair may be incorrect or insufficient.")
        return

    if len(candidates) == 1:
        recovered_key, a, b, recovered_plaintext = candidates[0]

        print("Attack Status         : UNIQUE MATCH FOUND")
        print("\nRecovered Key Details")
        print("Recovered Vigenere Key:", recovered_key)
        print("Recovered Affine A    :", a)
        print("Recovered Affine B    :", b)
        print("Recovered Plaintext   :", recovered_plaintext)
        print(
            "Known plaintext verified:",
            recovered_plaintext[:len(known_plaintext)] == known_plaintext
        )
    else:
        print("Attack Status         : AMBIGUOUS")
        print("More than one key combination matches the known plaintext.")
        print(
            "Provide a longer and less repetitive known-plaintext portion."
        )
        print("\nFirst candidate examples:")

        for index, (key, a, b, _) in enumerate(candidates[:5], start=1):
            print(f"{index}. Key={key}, A={a}, B={b}")

        if len(candidates) > 5:
            print(f"... and {len(candidates) - 5} more candidates.")


# ==================== ATTACK PERFORMANCE METRICS ====================

def attack_performance_comparison():
    """
    Runs repeated known-plaintext attack trials at different ciphertext
    lengths. The attacker receives only a 55-character plaintext prefix.
    The original plaintext is used only by the benchmark to score recovery.
    """
    print("\n" + "-" * 85)
    print("KNOWN-PLAINTEXT ATTACK PERFORMANCE")
    print("-" * 85)

    print(
        f"{'Cipher Length':<16}{'Known Length':<15}"
        f"{'Success Rate':<16}{'Candidates':<13}"
        f"{'Median Time (s)':<18}{'Char Checks':<15}"
    )

    trial_count = 5
    known_length = KEY_LENGTH * 5

    for n in (1000, 10000, 100000):
        successful_trials = 0
        candidate_counts = []
        trial_times = []
        character_checks = []

        for trial in range(trial_count):
            # Deterministic but different test data for reproducibility.
            rng = random.Random(1000 + n + trial)
            sample = ''.join(
                rng.choices(string.ascii_uppercase, k=n)
            )
            test_ciphertext = hybrid_encrypt(sample)
            known_prefix = sample[:known_length]

            start = time.perf_counter()
            candidates, effort = find_attack_candidates(
                test_ciphertext, known_prefix
            )
            trial_times.append(time.perf_counter() - start)

            candidate_counts.append(len(candidates))
            character_checks.append(effort["character_checks"])

            # Scoring uses the known benchmark plaintext, not the attack.
            if (
                len(candidates) == 1
                and candidates[0][3] == sample
            ):
                successful_trials += 1

        success_rate = (successful_trials / trial_count) * 100
        median_time = sorted(trial_times)[len(trial_times) // 2]
        average_candidates = sum(candidate_counts) / trial_count
        average_checks = sum(character_checks) // trial_count

        print(
            f"{n:<16}{known_length:<15}"
            f"{success_rate:>6.1f}%{'':<10}"
            f"{average_candidates:<13.1f}"
            f"{median_time:<18.8f}{average_checks:<15}"
        )

    print("\nTrials per ciphertext length:", trial_count)
    print("Success means one candidate recovered the complete test plaintext.")
    print(
        "The benchmark's original plaintext is used only to score the attack; "
        "it is not passed to the attack function."
    )


# ==================== TIMING COMPARISON ====================

def measure_time(function, text, repeats=5):
    timings = []

    for _ in range(repeats):
        start = time.perf_counter()
        function(text)
        timings.append(time.perf_counter() - start)

    timings.sort()
    return timings[len(timings) // 2]


def efficiency_comparison():
    print("\n" + "-" * 75)
    print("EFFICIENCY COMPARISON")
    print("-" * 75)

    print(
        f"{'Length':<12}{'Hybrid Enc':<15}{'Hybrid Dec':<15}"
        f"{'Shift Enc':<15}{'Shift Dec':<15}"
    )

    for n in (1000, 10000, 100000):
        random.seed(1)

        sample = ''.join(
            random.choices(string.ascii_uppercase, k=n)
        )

        hybrid_cipher = hybrid_encrypt(sample)
        shift_cipher = shift_encrypt(sample)

        hybrid_enc_time = measure_time(hybrid_encrypt, sample)
        hybrid_dec_time = measure_time(hybrid_decrypt, hybrid_cipher)
        shift_enc_time = measure_time(shift_encrypt, sample)
        shift_dec_time = measure_time(shift_decrypt, shift_cipher)

        print(
            f"{n:<12}{hybrid_enc_time:<15.6f}{hybrid_dec_time:<15.6f}"
            f"{shift_enc_time:<15.6f}{shift_dec_time:<15.6f}"
        )

    print("\nBoth ciphers have O(N) encryption and decryption complexity.")
    print("The hybrid normally performs more operations because it has two stages.")


# ==================== TIME COMPLEXITY ====================

def display_complexity():
    print("\n" + "-" * 55)
    print("TIME COMPLEXITY ANALYSIS")
    print("-" * 55)

    print("Hybrid encryption       : O(N)")
    print("Hybrid decryption       : O(N)")
    print("Shift encryption        : O(N)")
    print("Shift decryption        : O(N)")
    print("Known-plaintext attack  : O(K x L + S x N)")
    print("K = Candidate key pairs (312)")
    print("L = Known plaintext length")
    print("S = Matching candidate keys")
    print("N = Ciphertext length")


# ==================== MAIN PROGRAM ====================

def main():
    validate_keys()

    print("=" * 60)
    print("       VIGENERE-AFFINE HYBRID CIPHER")
    print("=" * 60)

    plaintext = input("Enter plaintext (A-Z only): ").strip().upper()

    if not valid_text(plaintext):
        print("Error: Enter letters A-Z only, without spaces or symbols.")
        return

    # ==================== ENCRYPTION ====================

    print("\n" + "-" * 55)
    print("ENCRYPTION")
    print("-" * 55)

    start = time.perf_counter()
    stage1 = vigenere_encrypt(plaintext, VIGENERE_KEY)
    vigenere_enc_time = time.perf_counter() - start

    print("\nStage 1: Vigenere Encryption")
    print("Plaintext             :", plaintext)
    print("Vigenere Key          :", VIGENERE_KEY)
    print("After Vigenere        :", stage1)
    print(f"Stage 1 Time          : {vigenere_enc_time:.8f} seconds")

    start = time.perf_counter()
    ciphertext = affine_encrypt(stage1, AFFINE_A, AFFINE_B)
    affine_enc_time = time.perf_counter() - start

    print("\nStage 2: Progressive Affine Encryption")
    print("Affine A              :", AFFINE_A)
    print("Affine B              :", AFFINE_B)
    print("Final Ciphertext      :", ciphertext)
    print(f"Stage 2 Time          : {affine_enc_time:.8f} seconds")

    total_encrypt_time = vigenere_enc_time + affine_enc_time
    print(f"\nTotal Encryption Time : {total_encrypt_time:.8f} seconds")

    # ==================== DECRYPTION ====================

    print("\n" + "-" * 55)
    print("DECRYPTION")
    print("-" * 55)

    start = time.perf_counter()
    intermediate = affine_decrypt(ciphertext, AFFINE_A, AFFINE_B)
    affine_dec_time = time.perf_counter() - start

    print("\nStage 1: Progressive Affine Decryption")
    print("Ciphertext            :", ciphertext)
    print("After Affine Decrypt  :", intermediate)
    print(f"Stage 1 Time          : {affine_dec_time:.8f} seconds")

    start = time.perf_counter()
    recovered = vigenere_decrypt(intermediate, VIGENERE_KEY)
    vigenere_dec_time = time.perf_counter() - start

    print("\nStage 2: Vigenere Decryption")
    print("Vigenere Key          :", VIGENERE_KEY)
    print("Recovered Plaintext   :", recovered)
    print(f"Stage 2 Time          : {vigenere_dec_time:.8f} seconds")

    total_decrypt_time = affine_dec_time + vigenere_dec_time
    print(f"\nTotal Decryption Time : {total_decrypt_time:.8f} seconds")
    print("Decryption Correct    :", recovered == plaintext)

    # ==================== KNOWN-PLAINTEXT ATTACK ====================

    print("\n" + "-" * 55)
    print("KNOWN-PLAINTEXT ATTACK INPUT")
    print("-" * 55)

    print(
        f"Enter a known plaintext prefix (at least {KEY_LENGTH} characters; "
        f"{KEY_LENGTH * 5} or more is recommended)."
    )
    print("The attacker must know this text and its matching ciphertext.")

    known_plaintext = input("Known plaintext (A-Z): ").strip().upper()

    if not valid_text(known_plaintext):
        print("Invalid input: enter letters A-Z only, without spaces or symbols.")
    elif len(known_plaintext) > len(ciphertext):
        print("Invalid input: known plaintext cannot exceed ciphertext length.")
    else:
        # Do not compare with the original plaintext here.
        # In a real known-plaintext attack, the attacker does not know
        # the complete original plaintext.
        known_plaintext_attack(ciphertext, known_plaintext)

    # ==================== SHIFT CIPHER BASELINE ====================

    print("\n" + "-" * 55)
    print("SHIFT CIPHER BASELINE")
    print("-" * 55)

    shift_ciphertext = shift_encrypt(plaintext)
    shift_recovered = shift_decrypt(shift_ciphertext)

    print("Shift value           : 3")
    print("Plaintext             :", plaintext)
    print("Shift ciphertext      :", shift_ciphertext)
    print("Shift decrypted       :", shift_recovered)
    print("Shift correct         :", shift_recovered == plaintext)

    # ==================== BENCHMARK / COMPLEXITY ====================

    efficiency_comparison()
    attack_performance_comparison()
    display_complexity()

    print("\n" + "=" * 60)
    print("                 PROGRAM COMPLETE")
    print("=" * 60)


if __name__ == "__main__":
    main()
