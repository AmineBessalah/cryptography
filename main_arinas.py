import sys
import base64
from getpass import getpass
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
from cryptography.hazmat.primitives import hashes
from cryptography.fernet import Fernet, InvalidToken

def derive_key(password: bytes, salt: bytes) -> bytes:
    """
    Dérive une clé de 32 octets à partir d'un mot de passe et d'un sel,
    puis encode la clé en base64 pour l'utiliser avec Fernet.
    """
    kdf = PBKDF2HMAC(
        algorithm=hashes.SHA256(),
        length=32,
        salt=salt,
        iterations=100_000,
    )
    return base64.urlsafe_b64encode(kdf.derive(password))

IDENTITY_SALT = b"fixedsalt1234567"
IDENTITY_PASSWORD = b"gagalaxy"
identity_key = derive_key(IDENTITY_PASSWORD, IDENTITY_SALT)
identity_fernet = Fernet(identity_key)

encrypted_first_name = b'gAAAAABn5PIMyPCu3gm2PfFZr0EvQliCQkgNvLV0FQnpwKkI2dO_8Q2xfP_DYvLER7lYnyy_wutjY9d0oDeyxsLvduyhNN8kMw=='
encrypted_last_name  = b'gAAAAABn5PISC2MpQKowkTxIffYfEP14osexbxM4eSGl0Ce55k-IM2BGIJ85Z_m8zV16iirOqTuVj0NFUY2tupJWEDLWI-GCFQ=='
encrypted_brother    = b'gAAAAABn5PIQMGHB3P5VzANE36GaxUD5M_1zvkowfDD-iJyRIHfkQaxDRm2MH5siHekK4XEgH1nq1uxR8GbmwA7FUCc7G2evQg=='

def decrypt_value(encrypted_value: bytes, f: Fernet) -> str:
    """Décrypte une valeur avec le Fernet fourni et retourne la chaîne en clair."""
    try:
        return f.decrypt(encrypted_value).decode()
    except InvalidToken:
        sys.exit("Erreur de décryptage : Clé invalide ou données corrompues.")

ULTRA_SECRET_SALT = b"ultrasecretsalt1"
encrypted_secret_text = b'gAAAAABn5uJlau96_CtpjRUbQ-5O3yOIOyG1IuevSAdR_JQlMauvmlwnJ7OmGloBrvGRPfMExFFiyBsZwQ2_1y99FOyBmAK_uTDv3AfT0uVjFFIXQ7TYK1IGcEpTRIYYYFvelM1rw0udopSdp5dANwoG_E-wi_dpHjiJOPtDcDGTuTQ_WO2MubtaqjTB4noM8uE7lOCOrMQ1PPyPKD6BgGb8xfWw6FsPWtPI2Zp-W2Y8IrHOQDvivwbDUtQQV7e9SfMn9K23uAWArJNlzIW3xQIcnY5G0wpemnlSdrTc4W-LNsugRfB41tz6TTHap_1qNQvPjNBbLULvWNAHv6bqx5Nder5Hgad9v2e2UxXkwKWRRbQ-hQtB93FWdBb4D9Jis9rpVmRNBQDB7xVUbmifpVVB9zxjw46NiRabGQZDD1ONmpjB0N5ZAZ2iA7DjyQ8Guuynf18YLZqoInkO_bVor2y3J7hlrZPwM-fDGegt72eBkdpNfOyatrQL_UL1_GEaU1jTKA2eUtnW41wcXxxrE1-daXY1WApBOh7clrBc4_jouptVMofga-3DTC7Vuzx3kVx7-qYqLu6xZ6yRU96eh5LoM9O1kxGPBECHk15i1-le8NlbN0sERzP4CHTXt0H8di9d8qxB6gzm3Ct-R6z5uuqQBJ-PCRgPfwaHnV-WKY-_12o0aoj4_wkK3GiiNBS02ND0U1aduIiSTFCUXL-L99ubjaZbHHGohQKUY8eoaAW7233E14qVnk3PWHJJp2nDLnBzn1-A71xhDXczla2q5pIenNkFSjeEbN1B2ghEjE6vM9uruPfqUI-FOICMzqkq0jdYmWKgnnJEBNP3j4A6kyS8p41y16621GdK2oGHH-zkD0fNwjxTfhCZvUQICkLiMJQ4v0qbi4Bem9fsU1uKrg2LIQO2oaaz9l47UZOY8B1h_thf9JIwWF5JS3-fwwng1w7b4lJsui7fg3avHLZnFN85_qLMw3Co-cMbjTU5EYVCWo0IlZp-x9vj4h5diCTTz4OF701ArSd-ECwsm2zzYIY-7WhEWJ2odNJAE5HB9ZN-2gPIp_PtT6rDXKbs15p9HAZhn2QLsklxBFeCe-W4oI33GH1C3oCj8lClSrkmdMi390MOxkYYrZx8ONEwHJVRnwfOiyWIT2Qe7p9Atb8A6IthIB3xYBPZ70gHsxO0t-wFBq7zVzmwxdEAmKMDVUFMCddJN6yf0kali0WL8y03qE5OvcWnzWEwQ-0HpbO830DbVq22psFNTNVvBiMYszWqxigccLN8GrcI3HCQ3z-RzvhTAOynojoQI0DzPOmu_W9xQDRo4ZvhrxHM-2Vxf6DuaM51EKz3Z5U1EiIINlyW1XpUJ--DE-_j_XK2LM3b-MsyQt5D28zqzT2R5TM91ABB7jN-XM6a93KCcgcTixQQHX6jd9yonRpRUrMtANz-T7H81aij8isdlyjjtbbTTlfbqKm6er9TPmfhiMvY6lT2WJxvagotd9QntT1XhplI9zmC_vv8exvYSBWazEu-EamifovfI0MKRr7xF8OUmSYYUURGi776guSvygb0brSoR7sTyqtKnEnjLoa-VspdVHEquL4bbQkwaxABd4dHGGKKF7yg9u-kK9Vx-ZXt1dwK0-BLIrtzX_C191mwfToWikQRAyuppR1_HQMhh5O_YZiyTJMYOPnCQy2wfkcQ8Lbgq8cPaLtlbF-eIDpWq3UMR1-hTvY03IKjUuVPLglgG_dbnTZq8fR9VpulwZpgmNrAnBgmHLdU8C8Hla41fGJJw4s1cReoty2BFiiNO8M9G22RO5ocUD1VKvuICnJDmrYW8tQ6HgQabyNWcO-mEK9gfpFWjKdh8aNZer4UBshlws-EobPzCGs8zj51DTAvUJoxmIH2-nN9mUx4My7iUXE-GoaWIBRT0tUDE1ASpO5o5oxKLLgKgSYQ1Sa_1XzawdK4DJRlhY4FvspwytQP00owVwYY-58Vs4XZ0VHlb2GKH2icspog4225KQBp4ekmOreMieruVK99PpsZSlI='

def decrypt_ultra_secret(user_password: str) -> str:
    """Utilise le mot de passe utilisateur pour dériver une clé et déchiffrer le texte ultra secret."""
    user_key = derive_key(user_password.encode(), ULTRA_SECRET_SALT)
    ultra_fernet = Fernet(user_key)
    try:
        return ultra_fernet.decrypt(encrypted_secret_text).decode()
    except InvalidToken:
        sys.exit("Erreur : Le mot de passe secret est incorrect ou les données sont corrompues.")

def main():
    print("=== Application Ultra Secrète ===")
    print("Veuillez renseigner les informations personnelles pour accéder au texte ultra secret.\n")
    
    first_name = input("Entrez votre prénom : ").strip()
    last_name = input("Entrez votre nom de famille : ").strip()
    brother = input("Entrez le prénom de votre frère : ").strip()
    
    correct_first = decrypt_value(encrypted_first_name, identity_fernet)
    correct_last = decrypt_value(encrypted_last_name, identity_fernet)
    correct_brother = decrypt_value(encrypted_brother, identity_fernet)
    
    if first_name != correct_first or last_name != correct_last or brother != correct_brother:
        print("\nAccès refusé. Les informations fournies sont incorrectes.")
        sys.exit(1)
    
    print("\nIdentité vérifiée avec succès.")
    
    user_secret = getpass("Entrez le mot de passe secret pour déchiffrer le texte ultra secret : ").strip()
    ultra_secret_text = decrypt_ultra_secret(user_secret)
    
    print("\n=== Accès Autorisé ! ===")
    print("\nVoici le texte ultra secret :\n")
    print("-" * 80)
    print(ultra_secret_text)
    print("-" * 80)
    
    file_name = "Texte_Ultra_Secret_Pour_Arinas.txt"
    try:
        with open(file_name, "w", encoding="utf-8") as f:
            f.write(ultra_secret_text)
        print(f"\nLe texte ultra secret a été sauvegardé dans le fichier '{file_name}'.")
    except Exception as e:
        print("Erreur lors de la sauvegarde du fichier :", e)
    
    print("\nCreated By Amine for Arinas")

if __name__ == "__main__":
    main()
