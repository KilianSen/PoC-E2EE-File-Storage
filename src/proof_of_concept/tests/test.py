import unittest
import os
import json
from src.proof_of_concept import (
    register, login, logout, get_files, upload, download, delete, delete_user, password_decrypt, password_encrypt
)
from cryptography.fernet import Fernet

class TestCryptoFunctions(unittest.TestCase):
    def test_encrypt_decrypt_message(self):
        message = b"Secret Message"
        password = "strongpassword"
        encrypted = password_encrypt(message, password)
        decrypted = password_decrypt(encrypted, password)
        self.assertEqual(message, decrypted)

    def test_decrypt_with_wrong_password(self):
        message = b"Secret Message"
        password = "strongpassword"
        wrong_password = "wrongpassword"
        encrypted = password_encrypt(message, password)
        with self.assertRaises(Exception):
            password_decrypt(encrypted, wrong_password)

    def test_encrypt_empty_message(self):
        message = b""
        password = "strongpassword"
        encrypted = password_encrypt(message, password)
        decrypted = password_decrypt(encrypted, password)
        self.assertEqual(message, decrypted)

    def test_decrypt_tampered_token(self):
        message = b"Secret Message"
        password = "strongpassword"
        encrypted = password_encrypt(message, password)
        tampered_encrypted = encrypted[:-1] + b'0'
        with self.assertRaises(Exception):
            password_decrypt(tampered_encrypted, password)

class TestProofOfConcept(unittest.TestCase):

    def setUp(self):
        self.username = "testuser"
        self.password = "testpassword"
        self.file_path = "testfile.txt"
        self.download_path = "downloaded_testfile.txt"
        self.uri = None

        with open(self.file_path, "w") as f:
            f.write("This is a test file.")

    def tearDown(self):
        for file in ["users.json", "session.json", "files.json", self.file_path, self.download_path]:
            if os.path.exists(file):
                os.remove(file)
        if os.path.exists("storage"):
            for file in os.listdir("storage"):
                os.remove(os.path.join("storage", file))
            os.rmdir("storage")

    def test_user_registration(self):
        register(self.username, self.password)
        self.assertTrue(os.path.exists("users.json"))

    def test_user_login(self):
        register(self.username, self.password)
        login(self.username, self.password)
        self.assertTrue(os.path.exists("session.json"))

    def test_user_logout(self):
        register(self.username, self.password)
        login(self.username, self.password)
        logout()
        self.assertFalse(os.path.exists("session.json"))

    def test_file_upload(self):
        register(self.username, self.password)
        login(self.username, self.password)
        self.uri = upload(self.file_path)
        self.assertTrue(os.path.exists(f"storage/{os.path.basename(self.file_path)}"))

    def test_file_download(self):
        register(self.username, self.password)
        login(self.username, self.password)
        self.uri = upload(self.file_path)
        download(self.uri, self.download_path)
        self.assertTrue(os.path.exists(self.download_path))

    def test_file_delete(self):
        register(self.username, self.password)
        login(self.username, self.password)
        self.uri = upload(self.file_path)
        delete(self.uri)
        self.assertFalse(os.path.exists(f"storage/{os.path.basename(self.file_path)}"))

    def test_user_delete(self):
        register(self.username, self.password)
        login(self.username, self.password)
        delete_user()
        self.assertFalse(os.path.exists("users.json"))

    def test_file_upload_already_exists(self):
        register(self.username, self.password)
        login(self.username, self.password)
        upload(self.file_path)
        with self.assertRaises(ValueError):
            upload(self.file_path)

    def test_file_download_not_exists(self):
        register(self.username, self.password)
        login(self.username, self.password)
        with self.assertRaises(ValueError):
            download("zke2ee://nonexistent?k=nonexistent", self.download_path)

    def test_file_delete_not_exists(self):
        register(self.username, self.password)
        login(self.username, self.password)
        with self.assertRaises(ValueError):
            delete("zke2ee://nonexistent?k=nonexistent")

class TestMultipleUsersAndFiles(unittest.TestCase):

    def setUp(self):
        self.users = [
            {"username": "user1", "password": "password1"},
            {"username": "user2", "password": "password2"}
        ]
        self.files = ["file1.txt", "file2.txt"]
        for file in self.files:
            with open(file, "w") as f:
                f.write(f"This is {file}.")

    def tearDown(self):
        for file in ["users.json", "session.json", "files.json"] + self.files + [f"downloaded_{file}" for file in self.files]:
            if os.path.exists(file):
                os.remove(file)
        if os.path.exists("storage"):
            for file in os.listdir("storage"):
                os.remove(os.path.join("storage", file))
            os.rmdir("storage")

    def test_register_multiple_users(self):
        for user in self.users:
            register(user["username"], user["password"])
        self.assertTrue(os.path.exists("users.json"))

    def test_login_multiple_users(self):
        for user in self.users:
            register(user["username"], user["password"])
            login(user["username"], user["password"])
            self.assertTrue(os.path.exists("session.json"))
            logout()

    def test_upload_multiple_files(self):
        register(self.users[0]["username"], self.users[0]["password"])
        login(self.users[0]["username"], self.users[0]["password"])
        for file in self.files:
            upload(file)
            self.assertTrue(os.path.exists(f"storage/{os.path.basename(file)}"))
        logout()

    def test_download_multiple_files(self):
        register(self.users[0]["username"], self.users[0]["password"])
        login(self.users[0]["username"], self.users[0]["password"])
        uris = [upload(file) for file in self.files]
        for uri, file in zip(uris, self.files):
            download_path = f"downloaded_{file}"
            download(uri, download_path)
            self.assertTrue(os.path.exists(download_path))
        logout()

    def test_delete_multiple_files(self):
        register(self.users[0]["username"], self.users[0]["password"])
        login(self.users[0]["username"], self.users[0]["password"])
        uris = [upload(file) for file in self.files]
        for uri in uris:
            delete(uri)
            self.assertFalse(os.path.exists(f"storage/{os.path.basename(uri)}"))
        logout()

    def test_delete_multiple_users(self):
        for user in self.users:
            register(user["username"], user["password"])
            login(user["username"], user["password"])
            delete_user()
            self.assertFalse(os.path.exists("users.json"))

if __name__ == "__main__":
    unittest.main()