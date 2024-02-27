```
def caesar_cipher(text, shift):
    encrypted_text = ""
    for char in text:
        if char.isalpha():  # Check if the character is an alphabet
            shifted = ord(char) + shift
            if char.islower():
                if shifted > ord('z'):
                    shifted -= 26
                elif shifted < ord('a'):
                    shifted += 26
            elif char.isupper():
                if shifted > ord('Z'):
                    shifted -= 26
                elif shifted < ord('A'):
                    shifted += 26
            encrypted_text += chr(shifted)
        else:
            encrypted_text += char
    return encrypted_text

def caesar_decipher(text, shift):
    return caesar_cipher(text, -shift)

# Example usage:
plain_text = "Hello, World!"
shift = 3
encrypted_text = caesar_cipher(plain_text, shift)
print("Encrypted:", encrypted_text)  # Outputs: "Khoor, Zruog!"
decrypted_text = caesar_decipher(encrypted_text, shift)
print("Decrypted:", decrypted_text)  # Outputs: "Hello, World!"

```
