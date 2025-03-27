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

# === Partie 1 : Vérification d'identité ===

# Pour la vérification d'identité, nous utilisons un mot de passe fixe "gagalaxy" et un sel fixe.
IDENTITY_SALT = b"fixedsalt1234567"  # 16 octets
IDENTITY_PASSWORD = b"gagalaxy"
identity_key = derive_key(IDENTITY_PASSWORD, IDENTITY_SALT)
identity_fernet = Fernet(identity_key)

# (Dans cet exemple, elles sont générées dynamiquement ; en prod
# Les valeurs correctes, stockées de manière cryptéeuction, elles devraient être pré-générées et stockées de manière sécurisée.)
encrypted_first_name = b'gAAAAABn5PIMyPCu3gm2PfFZr0EvQliCQkgNvLV0FQnpwKkI2dO_8Q2xfP_DYvLER7lYnyy_wutjY9d0oDeyxsLvduyhNN8kMw=='
encrypted_last_name  = b'gAAAAABn5PISC2MpQKowkTxIffYfEP14osexbxM4eSGl0Ce55k-IM2BGIJ85Z_m8zV16iirOqTuVj0NFUY2tupJWEDLWI-GCFQ=='
encrypted_brother    = b'gAAAAABn5PIQMGHB3P5VzANE36GaxUD5M_1zvkowfDD-iJyRIHfkQaxDRm2MH5siHekK4XEgH1nq1uxR8GbmwA7FUCc7G2evQg=='

def decrypt_value(encrypted_value: bytes, f: Fernet) -> str:
    """Décrypte une valeur avec le Fernet fourni et retourne la chaîne en clair."""
    try:
        return f.decrypt(encrypted_value).decode()
    except InvalidToken:
        sys.exit("Erreur de décryptage : Clé invalide ou données corrompues.")

# === Partie 2 : Déchiffrement du texte ultra secret ===

# Pour le texte ultra secret, nous utiliserons une clé dérivée d'un mot de passe secret fourni par l'utilisateur.
ULTRA_SECRET_SALT = b"ultrasecretsalt1"  # 16 octets
encrypted_secret_text = b'gAAAAABn5PgrwiY69pGs8GzLnswGILc29ubpasf_ZZtP3rTSO9NRDzPm3_u6ibFoNmmX1ITFimQQIssZcFjB0l4eG5NwKzLK67p4-uyuzmbc5HEW1H-BmKS2YbzbewuDSg1mkFqUyXjGinIXqBoSYkCBQFhCol9vzImZwQ9uFKAuZtMX_2eR3raQZrf3p8ju5jng3Q9tvVb9yQ9_UWLQ7ghnuLEtx5QQFLiEMs5OszU5EWFwoK_ohBRgexo-aG0ccfsPVSI6wsft5qe7224Gc8vJ_NPFcKht2HYGtO3oMiUMCXF0lfJpeiTo-Zz2qFJlOsooAfagGakvadWrW3CtZyWEMus5qPPNIc1idfxap3QztFJHHksZjXDoLLgomDFaVioN4zw50VcwEXJ_epRpgRRhJAuPDx9bJFqXks2nGJL1vfcp5xEpqps2Xb7B3wpiMEbc0j9XpgOOTqoOdr3G9vxabjmEFCIlG_Oqz7V9c1WgUg_TgyZs3nCL14UPrmpZJsYsB32QbprlakhgeHdFXGsHPvBo4thbkGXTxDh8tWF0I-PvxEmSE2cL9z8j7k2qmuOINY_weYuNqotycfdrZzFUlyXnQrH-p6rY3js_Yqh3HlWwqDWn3sbm2RugjIQ4zhXypfRQVCdia8VdgO_Vjxc1pH2D9YAzsELn-CD6NV_kHy1RTDEZfAk06XyxisEoQEwyKaGF2t6XVzHKCUgNyKEIMzR4BRVWUAamPNjBvtCEFREAL4YW-wXVLTydmCp6DOxUdnPzjykqEUWkRgGv8QGcIEq6x2R0fhvsohqQ9bZSODjLVxf73PscCJHQeP8e248Ma2DXnF8ecGMEZ_ax2q1oxWhRMGZsgyIKGhZsVPnU-bGjxJKN5WEXzMRPsnv_peXn6lIYuOcQCD3ulvrVFJ72ahb9UJFPd0v0PHTzcJuuy_dsz_sDkWS3Qlsc6xtoU1aAsO_42sS20VMWjzQNereVbj2SmRMgN5jgYg7v_Oehnac3Jxd-XsDSnQeJT0M7ExN5KmAhtBpQ_EA9a4flRMKXarz9Kb-LR2-kXonV80aQKWstFzuu7VcU7awk0IMr8dDCeEoU5IbTCB1vOLm2laRADGiqo-TD7o-y467A1d1Y1XDiIs644KsA2RBAiyHNn6W-J7G59kke8iFh8fD4skyGvbD9JMET0BdTWJl9uTFyrYrXLrJOPzQuvuXX7FMbC5ny_22fVSrrepG_0g3MG4HaEt1d7oDoYVCaofcfWlBBAvhnrFi-svrD7DFJqmd1Hx_tgwYhLLPSKyKDTlVjogLUrgsPaXW1CiCD_nNruOmPnCzTJU1_2Ee8dIP654WtK6oVkBDAyCIhEi1lAwHhDLGqIHLW8gABwCtxuaQXA3aiBhKJ6GM64zADzbb6Nj-c_-pZlwqSNQc0w4j6QRu22ixWGYMW1YPgEc5uYP2a4u-xBGqkKvaz9qIFgK9Z6s2uLEbb8sjNZcjbJM719FVUftl2KZr_w2aQ48C31Yq0VGnV1JqijiKEay5wowfPdLQ2QxcGqTKXtuH4GZdX6ppva4XBPB4udX8sUCd52QZyzLorUJ1sm-Y0k77A1KmgcX-rIWo2w7f9FghW5XE_mRHJvrq8NlGjeJWilqZ5s_FuWOjFsxWnfei2x5No9h1_BAvuAKXLD-2RzNRFWnGzZp4xXz0sgnzl_tIfiKaT9TwiNyTgCwlVPEgQtaizL_8Ls8AyYCiIjOZY5ieAAUBxk8p85ZhRqQEOLuA1EF73-IZNoxYfqaETEUdD95KxlVoj_BF5TmR5H9evSwTS0p_RxCaGzoPmyGQNmFL0L7FM_ojAisuy0Oq50qE2ssG_DcqIUb-FIp5Ua27kkut4b5l0r41fVSZHjQICWgGbxIo0ccEbGuPSzquqfTYA5YsX1JPAx0WzV1l5RDFrumd4bSdMnd2c2BlG0fre5NbYFD19LkkljQt6fdCDuILW6Hg3b88HOnfTaVSHzmfEsToqptNlTJOwDO7yXIrsQ8OHZG47tEAxejqenFf_HE0v91OvwIlraVWwpPe9Zi8Eh6Bf7UW0H_7DVC8RN39zfPNRXmxvgUQgOPVFnPMiu2b3Wj1lLNWB89v4sn6hXiG7YTmWl4evqh8lM7hQ3a0hcG-FedstDVIXRa3oNAtU432ROhZmEYL4gdV3BERHcA71FxkWyx83a-MJADtC4BNOEC5pgUZ7FY3M-blw3SEN9Pb4Tlqhb-i8TbLU5eICWNRJYRCR1tPDhP0XveXu1_SxdCn_ooIoFaU5HrJeXkN7GmYRLDtZ0CKEp_Ocl1MuT5-Tmm8z6oJF9NW7eeqUXapiRM7dXOFyMQG_1BUnE_LAt9SfjJQ26AIWGsezcGmlIrvh1GGdp4gWhKf6rcPIvmeFZQeYMFOAc2-WRyzQo0XLzSmri3wefyquMGJM2a8M3oAuoxXhbXWe43HV_YYSL6CtjqPshmrNzz8rlHuj1YFxi6ht6P9SD1QGtew5qSQWkX7Qjh7F6DxuBpU39x2mJplskDhAWjhd-KYtG1XF8wsua7ZsGgmAOyhqFV-nREHJqZgGhXK0Wp5PSMhgSdnDQRQPJjbGCv5_uGCJHEBJwHF_S1h_PCop-sdQZx7b72GTzXSdHR-_QiSO57uNX2HFAYxi_SQdijsPfTKhEAzocoQeHAxWbT5T0ZMyJpFay_6UIPuUNPTgV9VyiRa_OA7GNf2CTvK-dzD8v0iPAMv2In35h99JwA1s3qzpF_HGO3e6er5mixqEyA7cdtxgIlglAnGOfgplQI1Qaof9jFL-ygo5FFWEX_ImPrG1jw7-qm2oOIQ2kZDEEuzPUJs60fE5h-D7Izxz15Y3PwM8Zo69BoG3iDEm5JYH65xYVqx72BGQOutuJFaNk8_V5U-mbm2PurqOH4xVUPK3agfJuekGRo9T4MlBup2UZ2cIYKRON1z7K4KFaWprdt993G-NdB-bo7Z6tfXFVL4MbjkEbR20KzAi0d_wlTzFzDfgr_VuH67Tkf55yCBVn6eb8rRN6UPgqzCyEfmOBUtu9CIOMnAf-UIFi2ILyPtFo4lBZhNasqAV1IJWNAtPlaN6Il8JxVf2InQC4-0toGQ3me7k00lmupP1SvKANdkyXp9ZWqFC-bJ17SoZW2DCm6LMd9OTUKYnbX35N0gZXt09qzy3rw1LRs-lswqSJDvlkws6TZcl3BcpG2VnPF2x1zN9k9wX6ymhZHg0uu63ZCdWEhmExdVJ7DvU9ZyrvqJuXZtifmMDBav-WGPp9zL87HW2opytdjgNTbVCvH2_p8bebxFQ2QIpKNLUMeEzHZQeQxPSanLReWqAXFYBy894RAl00QFcn8TDpPJ6WAXkt7IntO42O-iR71-X82cb6YDx_AeHmtgJjWf6E66z220V67nfthiA0b-DIZR4dx1eLLlPC6VWqd6xJtwFI28Q1TJ-7Uum86h1L47XqqXBuBn_PZStfAhjIZERJAhfC8yye2V5TKl2mMhsYRDGkYXHb5x1nmPjaONERfmaYoIh3wrkzDm8uNYY8T6lhNcuw7rTeY3lQypDaL25M_4YAa2WhEC1tr5C5Y2MLiO8uFRZfN3gfv_-Kuxl9MeABGboMYdncGposO5jYkmmC4-BDSy8AOgT6ifYbQhUWp7LK1yAlqN-hU5HOi8RKUesllJ4TS48vMGI74sfdsDAalbuj1jjT_wbO5xJ1P5TxXNT8xp4E0NaBfzrX-VjbZ6nkymA4JahlZ6KXGi0LcEWe_hmGTiDXjDsuLHp_e8h66hqGgaDd1WZU5ViDkQzMlzQuXyLducoZQnIWfNJb3bwAiS1tRtqCs8RiC6UyTe3-fMqs-O9fR_EF28J3rathKaZUTjWabjmDXyl54ZH6wFDIpPPkrPKEbbHh4B3uy5EtYAvG3i4C3zqjUjgeKSMdryhBo6JNrzURH_UuPYRrK8ImiBld3Xfc-gJZ1k8UBzoVayeN5Yv3rKT0WShHsmznpAE4vWYFFTZvZOUhD95re5z1dzwquHwIqO-FeZuM4c6PhU2S3iOab61V0VXjEoI7LvkKDLSb2QTlKIjt3NMF1aAF3bVvv5NRVZu0l21vtt4EmJ3HVUUoFh0hdrGn-f6DiPzkZmQBxOP1es1Mxsi_H_KbAukCn9yxl5b01Z_ATD_rUkNfSSuCm1vBsRW5nE2j4NBzt2Dr2BJ7yvfosNf1w1-pKpoNzgNcaZFYboUyZiqk6Ts5OlBl2cc4n2n9gZC1x7K4Mvu2o3OjRWgmaQSpvjgw06jU6WTlpECJWD5P6v0OpyBhW_Dsi1tPIq6BGYhcGMZs2YJhPqPg3nlHcpVQifFiHfKgO3RnoC9QjXtXw9cEPyrklWhYhdqmmGXpwQC07c7BeSAlSsrr2OSP77PsLQMrNYWL001PCfSkyVCygVZQUbU4wSmB0XAgm8hvWaN1mVooJ_8q4qiclH8-TgWMp8oQVkXMJDe-fEHuFaBTEfOIYZKpibghcYBcqPh0rUD17P06qrFCOp5suih1Pw6lnkqbxXURw_rQRwqdLN3GcesXKeZJCX2kKOmOT6u99xZwzOtqcXEQy3OC823n7EH3qGvtMKUa5B5LwVMo_8Db7UzEqEzmvfam8AvGWAcasZaBdTxt1XMd1ez-3iO_U3ClIzCdKP92BjgKs5cbSzwGVFHuqIBDpg0atSOw2p0hKtsNLNUyZUlj-99frupwyLSC6AS2ECvtAXOHMLhsAA5wLmtvLxBSz5-AYfJLPsfvDIsmxJQ3YANkDYX0dPHM09WNu6IQr7_dSraELo9ov6GM7Z-LZ7LCxnoSroelWlmfeC3KTmSzqSEbEc40UUBm01Kk-P_Uv1sJaud3HzICHuqFJeUsE-yB_FqftwYHcrqkD9_iW147gIQZZLFi0eOAlDJMjzmy7SiBjrm62LhaCywIwdUPZNLevS8bPxTHJp5Uk7ISJBZKrAXvi5It8iLBiF8MGTLM5zOKflYamqIxIbMjt_uRxJt9kcSmMi8rRT_eCMteVp64uoFaj7TQldQTVSg1_XjyyjRVVabHkJ-MsQp28bb3BDbbEbtQLakDpH3KJdQYrHEc_XhzxrhmqK0-ch5jBxDcxZvDm7EKNTPf33OMWQVtHwoUy1VK0LwX2OzG3ZTQbqYHjTUCu1zBvaGzynYV4OTMAUPNfX_aDtiVUzDcOwuhogUVhPiVmnIa0ah5Shma8HNty-jLhKgdENt9n0ovAOG8EJzxufPQphiVVky7flXI_ht4kNDheurUoywoSFx_Qj5ajuiSO2-bB3ULv29Vq5KNg-_oRNVG17GMQ4gH4nn0CSldGO6WKGv3Ack7Cy8KU275WvHSRjlLaB09DNyCbmlxLTLjxXPRK0e0y2yPLhFBW8yc2luMfjbPT4N5Iyfq68pj8w8Wlwc6f5A_mToz-rv_HsXCj3UrjSBkO-UJe02BvBgCeiTZIkG1Yx0cmzwpWbUpUJOhzjZ8jNOA7dixCukQwWRaEBwAmSuq78EuKIuaRUOJg7gSCr4hOt82W0C-BhxVXVbkHqy1Mge0a9N_KvdEaFVuwNGIJk6rO5XZ6mjsn5UP3CxS4-nEOBls-uBf5lT83iETOhBZuawsA95VxAAkQNoRzdE2VIA4Bmr1ueXCsxaAbjahD9a_84NQ13vXSqGtZ942InOsR3YcQd3Kzm_uqTsXO9WdZs2meaE7rrV-thUbVEWWJCN2hxosdyC9rh0n9WFaPR0Cp1W686sy72K1IDgcvK3hYNGUxhirYtVfNcVRTiD4c63'

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
    
    # Vérification d'identité
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
    
    # Demander le mot de passe pour déchiffrer le texte ultra secret
    user_secret = getpass("Entrez le mot de passe secret pour déchiffrer le texte ultra secret : ").strip()
    ultra_secret_text = decrypt_ultra_secret(user_secret)
    
    print("\n=== Accès Autorisé ! ===")
    print("\nVoici le texte ultra secret :\n")
    print("-" * 80)
    print(ultra_secret_text)
    print("-" * 80)
    
    # Sauvegarder le texte dans un fichier
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
