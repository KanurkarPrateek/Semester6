from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.fernet import Fernet


class EmployeeDataHandler:
    def __init__(self):
        # Generate a key pair for asymmetric encryption (for Authenticity)
        self.private_key, self.public_key = self.generate_key_pair()

        # Generate a key for symmetric encryption (for Confidentiality)
        self.key = Fernet.generate_key()
        self.cipher_suite = Fernet(self.key)

    def generate_key_pair(self):
        private_key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=2048,
            backend=default_backend()
        )
        public_key = private_key.public_key()
        return private_key, public_key

    def encrypt_sensitive_data(self, sensitive_data):
        # Confidentiality: Encrypt sensitive data
        encrypted_data = self.cipher_suite.encrypt(sensitive_data.encode())
        return encrypted_data

    def decrypt_sensitive_data(self, encrypted_data):
        # Confidentiality: Decrypt sensitive data
        decrypted_data = self.cipher_suite.decrypt(encrypted_data).decode()
        return decrypted_data

    def calculate_hash(self, data):
        # Integrity: Calculate hash
        digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
        digest.update(data.encode())
        return digest.finalize()

    def sign_data(self, data):
        # Authenticity: Sign data
        signature = self.private_key.sign(
            data.encode(),
            padding.PSS(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return signature

    def verify_signature(self, data, signature):
        # Authenticity: Verify signature
        try:
            self.public_key.verify(
                signature,
                data.encode(),
                padding.PSS(
                    mgf=padding.MGF1(algorithm=hashes.SHA256()),
                    salt_length=padding.PSS.MAX_LENGTH
                ),
                hashes.SHA256()
            )
            return True
        except Exception:
            return False


# Example usage:
data_handler = EmployeeDataHandler()

# Simulating employee data
employee_data = {
    'employee_id': '12345',
    'name': 'John Doe',
    'position': 'Software Engineer',
    'salary': '100000',
    'email': 'john.doe@example.com',
}

# Define which fields are sensitive and should be encrypted
sensitive_fields = ['salary', 'email']

# Encrypt and sign sensitive data
encrypted_employee_data = employee_data.copy()
for field in sensitive_fields:
    if field in encrypted_employee_data:
        encrypted_employee_data[field] = data_handler.encrypt_sensitive_data(employee_data[field])
        # Calculate hash and sign for each sensitive field
        hash_value = data_handler.calculate_hash(employee_data[field])
        signature = data_handler.sign_data(employee_data[field])
        encrypted_employee_data[field + '_hash'] = hash_value
        encrypted_employee_data[field + '_signature'] = signature

# Decrypt and verify sensitive data
decrypted_employee_data = encrypted_employee_data.copy()
for field in sensitive_fields:
    if field in decrypted_employee_data:
        decrypted_employee_data[field] = data_handler.decrypt_sensitive_data(encrypted_employee_data[field])
        # Verify hash and signature for each sensitive field
        is_integrity_verified = hash(decrypted_employee_data[field]) == int.from_bytes(
            encrypted_employee_data[field + '_hash'], byteorder='big')
        is_authentic = data_handler.verify_signature(decrypted_employee_data[field],
                                                     encrypted_employee_data[field + '_signature'])
        decrypted_employee_data[field + '_integrity_verified'] = is_integrity_verified
        decrypted_employee_data[field + '_authentic'] = is_authentic

# Display results
print("Original Employee Data:")
print(employee_data)

print("\nEncrypted Sensitive Data:")
print(encrypted_employee_data)

print("\nDecrypted Sensitive Data:")
print(decrypted_employee_data)
