import os
import base64
import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Dérive une clé de 32 octets à partir du mot de passe et du sel, puis encode en base64 pour Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    key = base64.urlsafe_b64encode(kdf.derive(password))
    return key

def encrypt_data(data: str, password: str) -> bytes:
    """
    Crypte le texte 'data' avec un mot de passe.
    Retourne le sel (16 octets) suivi des données cryptées.
    """
    salt = os.urandom(16)  # Génère un sel aléatoire de 16 octets
    key = derive_key(password.encode(), salt)
    fernet = Fernet(key)
    token = fernet.encrypt(data.encode())
    return salt + token  # Le fichier contiendra le sel suivi des données cryptées

def decrypt_data(encrypted_data: bytes, password: str) -> str:
    """
    Décrypte les données. Le sel est stocké dans les 16 premiers octets.
    """
    salt = encrypted_data[:16]
    token = encrypted_data[16:]
    key = derive_key(password.encode(), salt)
    fernet = Fernet(key)
    decrypted = fernet.decrypt(token)
    return decrypted.decode()

def main():
    print("=== Application de Cryptage/Décryptage === (PS islam le mdp=mdp baridiweb (whatsapp))")
    print("1: Crypter des données")
    print("2: Décrypter des données")
    choice = input("Choisissez une option (1 ou 2): ").strip()

    if choice == "1":
        data = input("Entrez le texte à crypter: ")
        password = getpass.getpass("Entrez le mot de passe: ")
        encrypted = encrypt_data(data, password)
        file_name = input("Entrez le nom du fichier pour sauvegarder (ex: data.txt): ").strip()
        with open(file_name, "wb") as f:
            f.write(encrypted)
        print("Données cryptées enregistrées dans", file_name)
    elif choice == "2":
        file_name = input("Entrez le nom du fichier à décrypter (ex: data.txt): ").strip()
        try:
            with open(file_name, "rb") as f:
                encrypted = f.read()
        except FileNotFoundError:
            print("Fichier introuvable!")
            return
        password = getpass.getpass("Entrez le mot de passe: ")
        try:
            decrypted = decrypt_data(encrypted, password)
            print("\n--- Texte Décrypté ---")
            print(decrypted)
            print("----------------------")
        except InvalidToken:
            print("Mot de passe incorrect ou données corrompues!")
    else:
        print("Option invalide.")

if __name__ == "__main__":
    main()
