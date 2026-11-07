
# Vigenere–Progressive Affine Hybrid Cipher

**Course:** Network and Information Security (CT-486)  
**University:** NED University of Engineering & Technology  
**Project Type:** Complex Computing Problem (CCP)

---

## Project Overview

This project designs and implements a custom hybrid cipher by combining two classical encryption techniques:

1. **Vigenere Cipher** – First encryption stage.
2. **Progressive Affine Cipher** – Second encryption stage.

The project also implements a **Known-Plaintext Attack** to recover the encryption key and decrypt the complete message using a known plaintext prefix and its corresponding ciphertext.

Additionally, the program compares the hybrid cipher's performance with a single-stage Shift Cipher and analyzes the time complexity of encryption, decryption, and attack algorithms.

---

## Group Members

- **Aiman Nasir** (CR-23049)
- **Atika Imam** (CR-23008)
- **Soha** (CR-23027)
- **Ramaize Shahab** (CR-23035)

---

## Cipher Design

The custom cipher combines two classical encryption techniques in two sequential stages.

### 1. Vigenere Cipher

The first stage encrypts the plaintext using a repeating key.

- **Vigenere Key:** `NETWORKSAFE`
- **Key Length:** 11 characters

**Encryption Formula:**

$$
V_i = (P_i + K_{i \bmod 11}) \bmod 26
$$

Where:

- `P_i` = Plaintext character value.
- `K_i` = Corresponding key character value.
- `V_i` = Output of the Vigenere encryption stage.

### 2. Progressive Affine Cipher

The second stage applies a position-dependent Affine transformation.

- **Affine A:** 5
- **Affine B:** 8

**Encryption Formula:**

$$
C_i = (5V_i + 8(i+1)) \bmod 26
$$

The shift changes according to the character's position in the message.

### Combined Encryption Process

The encryption process follows these steps:

1. Take the plaintext as input.
2. Encrypt it using the Vigenere Cipher.
3. Apply the Progressive Affine Cipher to the intermediate result.
4. Generate the final ciphertext.

---

## Decryption

Decryption reverses both encryption stages.

The modular inverse of 5 modulo 26 is 21.

$$
5^{-1} \bmod 26 = 21
$$

**Step 1: Reverse Progressive Affine Cipher**

$$
V_i = 21(C_i - 8(i+1)) \bmod 26
$$

**Step 2: Reverse Vigenere Cipher**

$$
P_i = (V_i - K_{i \bmod 11}) \bmod 26
$$

The recovered plaintext is compared with the original plaintext to verify successful decryption.

---

## Known-Plaintext Attack

The project implements a Known-Plaintext Attack to simulate an attacker recovering the encryption keys.

The attacker is assumed to know:

- A portion of the original plaintext.
- The corresponding ciphertext.
- The Vigenere key length (11 characters).

The original encryption key is not provided to the attack function.

### Attack Methodology

1. Generate all valid Affine A values for which `gcd(A, 26) = 1`.
2. Test all 26 possible values of B.
3. Reverse the Progressive Affine transformation.
4. Derive Vigenere key characters using the known plaintext and corresponding ciphertext.
5. Check consistency at repeated Vigenere key positions.
6. Verify each candidate against the complete known plaintext portion.
7. Decrypt the full ciphertext only after a candidate key has been verified.

### Attack Search Space

There are 12 valid values of A and 26 possible values of B.

$$
12 \times 26 = 312
$$

Therefore, the attack tests **312 candidate Affine parameter pairs**.

At least 11 known plaintext characters are required to derive all Vigenere key positions. The program recommends a longer known plaintext prefix, and the benchmark uses 55 known characters.

---

## Shift Cipher Baseline

A traditional Shift Cipher with a fixed shift value of **3** is implemented as a baseline.

The program compares:

- Hybrid Cipher Encryption
- Hybrid Cipher Decryption
- Shift Cipher Encryption
- Shift Cipher Decryption

This comparison demonstrates the additional computational operations required by the hybrid cipher.

---

## Performance Evaluation

The program measures encryption and decryption performance using different message lengths.

| Message Length | Test |
|---|---|
| 1,000 characters | Performance measurement |
| 10,000 characters | Performance measurement |
| 100,000 characters | Performance measurement |

Each timing measurement uses five repeated runs and reports the median execution time.

### Known-Plaintext Attack Performance

The attack benchmark uses:

- 5 trials per ciphertext length.
- 55 known plaintext characters.
- Three different ciphertext lengths.

The program measures:

- **Success Rate:** Percentage of successful attack trials.
- **Matching Candidates:** Number of recovered candidate keys.
- **Median Attack Time:** Median execution time.
- **Character Checks:** Number of character comparisons performed.

The report's benchmark results show a 100% success rate and one matching candidate for each tested ciphertext length.

> Execution times may vary depending on the system and runtime environment.

---

## Time Complexity Analysis

| Algorithm | Time Complexity |
|---|---|
| Vigenere Encryption | O(N) |
| Progressive Affine Encryption | O(N) |
| Hybrid Encryption | O(N) |
| Hybrid Decryption | O(N) |
| Shift Encryption | O(N) |
| Shift Decryption | O(N) |
| Known-Plaintext Attack | O(K × L + S × N) |

**Where:**

- `N` = Plaintext or ciphertext length.
- `K` = Number of candidate Affine parameter pairs (312).
- `L` = Known plaintext length.
- `S` = Number of matching candidate keys requiring full decryption.

Both the hybrid cipher and Shift Cipher have linear encryption and decryption complexity. However, the hybrid cipher performs more operations because it uses two encryption stages.

---

## Security Analysis

The hybrid cipher combines two classical techniques, but it is still vulnerable to cryptanalysis.

The implemented Known-Plaintext Attack demonstrates that the encryption keys can be recovered under the tested conditions.

### Identified Security Limitations

- The Vigenere key is repeated.
- The same encryption key and Affine parameters are reused.
- The Progressive Affine transformation is mathematically predictable.
- The cipher does not provide modern authenticated-encryption protections.

### Suggestions for Security Improvement

1. Use randomly generated encryption keys instead of fixed keys and parameters.
2. Introduce a random starting offset for the progressive transformation.
3. Avoid reusing the same encryption keys for multiple messages.
4. Increase the complexity of key selection and reduce predictable patterns.
5. For real-world applications, use modern authenticated encryption algorithms such as AES-GCM or ChaCha20-Poly1305.

---

## Requirements

- Python 3.x
- No third-party libraries required.

The project uses Python standard-library modules:

- `time`
- `random`
- `string`
- `math`

---

## How to Run

**Step 1:** Clone or download this repository.

**Step 2:** Open the project directory in a terminal.

**Step 3:** Run the Python program.

```bash
python NIS_Project.py
```

**Step 4:** Enter a plaintext containing English letters A–Z. Lowercase letters are automatically converted to uppercase.

**Step 5:** Enter a known plaintext prefix matching the beginning of the original plaintext.

At least 11 characters are required, while 55 or more characters are recommended.

The program displays:

- Vigenere encryption output.
- Progressive Affine encryption output.
- Final ciphertext.
- Decryption results.
- Known-Plaintext Attack results.
- Recovered encryption keys.
- Shift Cipher baseline results.
- Encryption and decryption performance.
- Attack performance metrics.
- Time complexity analysis.

---

## Input Format

The program accepts non-empty English alphabetic text (A–Z).

- Lowercase letters are automatically converted to uppercase.
- Spaces are not accepted.
- Numbers are not accepted.
- Special characters and symbols are not accepted.

## Conclusion

This project demonstrates the design and implementation of a custom hybrid encryption algorithm using the Vigenere and Progressive Affine classical ciphers.

It successfully implements encryption, decryption, and a Known-Plaintext Attack that attempts to recover the encryption keys using only a known plaintext portion and its corresponding ciphertext.

The project also evaluates the computational performance of the hybrid cipher against a Shift Cipher and analyzes the time complexity of the implemented algorithms.

The results demonstrate that combining classical encryption techniques increases computational operations but does not guarantee modern cryptographic security.

---

**Course:** Network and Information Security (CT-486)  
**Project:** Design and Break a Custom Cipher Based on Classical Techniques

