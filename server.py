import os
import datetime
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization, hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import padding as sym_padding

# Hardcoded values
ca_identity = "ID-CA"
server_identity = "ID-Server"
client_identity = "ID-Client"
request_message = "memo"
service_data_message = "take cis3319 class this morning"
client_ip = "127.0.0.1"
client_port = "5000"
session_key_validity = 60


def get_current_timestamp():
    return datetime.datetime.now().strftime('%Y-%m-%d %H:%M:%S.%f')


def is_timestamp_valid(timestamp_str, validity_seconds):
    timestamp = datetime.datetime.strptime(timestamp_str, '%Y-%m-%d %H:%M:%S.%f')
    time_difference = datetime.datetime.now() - timestamp
    return time_difference.total_seconds() <= validity_seconds


# Generate Server's key pair
server_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
server_public_key = server_private_key.public_key()

# Generate CA's key pair
ca_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
ca_public_key = ca_private_key.public_key()

# Generate Client's key pair
client_private_key = rsa.generate_private_key(
    public_exponent=65537,
    key_size=2048,
    backend=default_backend()
)
client_public_key = client_private_key.public_key()

# Server's registration request (including a temporary DES key)
server_request = f"{server_identity} registration request with temp DES key: K$%&'".encode()

# Encrypt the request using CA's public key
encrypted_request = ca_public_key.encrypt(
    server_request,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("(step 1) Encrypted Server Request (Hex):", encrypted_request.hex())

# CA decrypts the request using its private key
decrypted_request = ca_private_key.decrypt(
    encrypted_request,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Decrypted Server Request:", decrypted_request.decode())

# CA create certificate for server
server_info = f"{server_identity} and other information".encode()
server_certificate = ca_private_key.sign(
    server_info,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)
print("(step 2) Server Certificate (Hex):", server_certificate.hex())

# Server receives and checks the certificate
try:
    ca_public_key.verify(
        server_certificate,
        server_info,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Server certificate verification success")
except Exception as e:
    print("Server certificate verification failed:", e)

# Client's registration request
client_request = f"{client_identity} registration request".encode()

# Encrypt the request using CA's public key
encrypted_client_request = ca_public_key.encrypt(
    client_request,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# CA decrypts the client's request using its private key
decrypted_client_request = ca_private_key.decrypt(
    encrypted_client_request,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Decrypted Client Request:", decrypted_client_request.decode())

# CA create certificate for client
client_info = f"{client_identity}, IP: {client_ip}, Port: {client_port}".encode()
client_certificate = ca_private_key.sign(
    client_info,
    padding.PSS(
        mgf=padding.MGF1(hashes.SHA256()),
        salt_length=padding.PSS.MAX_LENGTH
    ),
    hashes.SHA256()
)

# Encrypt client registration request
encrypted_client_info = server_public_key.encrypt(
    client_info,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("(step 5) Encrypted Client Info (Hex):", encrypted_client_info.hex())

# The server uses its private key to decrypt the client information
decrypted_client_info = server_private_key.decrypt(
    encrypted_client_info,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("Decrypted Client Info:", decrypted_client_info.decode())

# Client receives and checks the certificate
try:
    ca_public_key.verify(
        client_certificate,
        client_info,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    print("Client certificate verification success")
except Exception as e:
    print("Client certificate verification failed:", e)

# Encrypt the request_message using the server's public key
encrypted_request_message = server_public_key.encrypt(
    request_message.encode(),
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Server decrypts the client's request message using its private key
decrypted_request_message = server_private_key.decrypt(
    encrypted_request_message,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

print("Decrypted Client Request Message:", decrypted_request_message.decode())

# Generate a temporary session key (DES key)
session_key = os.urandom(16)

# Encrypt the session key using the client's public key
encrypted_session_key = client_public_key.encrypt(
    session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)
print("(step 6) Encrypted Session Key (Hex):", encrypted_session_key.hex())

# Simulate the client: Decrypt the session key using the client's private key
decrypted_session_key = client_private_key.decrypt(
    encrypted_session_key,
    padding.OAEP(
        mgf=padding.MGF1(algorithm=hashes.SHA256()),
        algorithm=hashes.SHA256(),
        label=None
    )
)

# Verify if the session key matches
if decrypted_session_key == session_key:
    print("Session key successfully exchanged and verified")
else:
    print("Session key exchange failed")

# Example: Secure communication using the session key
timestamped_service_data_message = f"{service_data_message} Timestamp: {get_current_timestamp()}".encode()
padder = sym_padding.PKCS7(128).padder()
padded_data = padder.update(timestamped_service_data_message) + padder.finalize()

# Server uses the session key to encrypt a service data message
cipher = Cipher(algorithms.AES(session_key), modes.ECB())
encryptor = cipher.encryptor()
encrypted_service_data_message = encryptor.update(padded_data) + encryptor.finalize()
print("(step 7) Encrypted Service Data Message (Hex):", encrypted_service_data_message.hex())

# Client uses the session key to decrypt the message
decryptor = cipher.decryptor()
decrypted_padded_message = decryptor.update(encrypted_service_data_message) + decryptor.finalize()

unpadder = sym_padding.PKCS7(128).unpadder()
decrypted_message = unpadder.update(decrypted_padded_message) + unpadder.finalize()

# Decrypt the message and verify the timestamp
decrypted_message_str = decrypted_message.decode()
timestamp_str = decrypted_message_str.split(" Timestamp: ")[-1]
if is_timestamp_valid(timestamp_str, session_key_validity):
    print("Timestamp is valid.")
    print("Decrypted message:", decrypted_message_str.split(" Timestamp: ")[0])
else:
    print("Timestamp is invalid or expired.")
