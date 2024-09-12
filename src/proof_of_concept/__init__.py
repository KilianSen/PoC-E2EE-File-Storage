import json
import os
from base64 import b64encode, b64decode

from argon2 import PasswordHasher
from cryptography.fernet import Fernet

from .crypto import password_encrypt, password_decrypt

def logged_in(should_be: bool = True):
    """
    Decorator to check if the user is logged in.
    Errors if the user is not logged in and
    should be or if the user is logged in and should not be.
    :param should_be: If the user should be logged in or not
    :return: Decorator
    """
    def decorator(func):
        def wrapper(*args, **kwargs):
            if should_be and not _is_logged_in():
                raise ValueError("You are not logged in")

            if not should_be and _is_logged_in():
                raise ValueError("You are already logged in")

            return func(*args, **kwargs)
        return wrapper
    return decorator

def _user_exists(username: str):
    if not os.path.exists("users.json"):
        return False

    with open("users.json", "r") as file:
        if username in json.load(file):
            return True

    return False

def _is_logged_in():
    if not os.path.exists("session.json"):
        return False

    return True

def _get_all_users():
    if not os.path.exists("users.json"):
        return {}

    with open("users.json", "r") as file:
        users = json.load(file)
        return users

def _get_all_files():
    if not os.path.exists("files.json"):
        return {user: [] for user in _get_all_users()}

    with open("files.json", "r") as file:
        return json.load(file)

def _get_uri(file: str, key: bytes) -> str:
    return f"zke2ee://{b64encode(file.encode()).decode()}?k={b64encode(key).decode()}"

def _get_file_from_uri(uri: str) -> tuple[str, bytes]:
    if not uri.startswith("zke2ee://") or "?k=" not in uri:
        raise ValueError("Invalid URI")

    identifier_split = uri.removeprefix("zke2ee://").split("?k=")
    key = identifier_split.pop()
    file = "?k=".join(identifier_split)

    file = b64decode(file).decode()
    key = b64decode(key)

    return file, key

@logged_in()
def _file_exists(file):
    return file in [ifile["file"] for ifile in get_files()]

@logged_in(False)
def register(username: str, password: str):
    if _user_exists(username):
        raise ValueError(f"User {username} already exists")

    if not os.path.exists("users.json"):
        with open("users.json", "w") as file:
            json.dump({}, file)

    # create a new user in the users.json file
    with open("users.json", "r") as file:
        users = json.load(file)
        password_hash = PasswordHasher().hash(password)
        users[username] = {"password_hash": password_hash, "file_encryption_key": password_encrypt(Fernet.generate_key(), password).decode()}

    with open("users.json", "w") as file:
        json.dump(users, file)

@logged_in(False)
def login(username: str, password: str):
    if not _user_exists(username):
        raise ValueError(f"User {username} does not exist")

    # verify the password
    with open("users.json", "r") as file:
        users = json.load(file)
        password_hash = users[username]["password_hash"]
        if not PasswordHasher().verify(password_hash, password):
            raise ValueError("Incorrect password")

    # create a session in the session.json file
    with open("session.json", "w") as file:
        json.dump(
            {
                "username": username,
                "file_encryption_key": password_decrypt(users[username]["file_encryption_key"], password).decode(),
            }, file)

@logged_in()
def logout():
    # delete the session file
    os.remove("session.json")

@logged_in()
def get_files() -> list[dict[str, str]]:
    with (open("session.json", "r") as session_file):
        session = json.load(session_file)
        session_files = _get_all_files()[session["username"]]

        decrypted_file_keys = [
            {"file": sfile["name"], "key": password_decrypt(sfile["key"], session["file_encryption_key"])}
            for sfile in session_files
        ]
        return decrypted_file_keys

@logged_in()
def upload(path: str):
    if not os.path.exists(path):
        raise ValueError(f"File {path} does not exist")

    with open("session.json", "r") as file:
        session = json.load(file)
        username = session["username"]
        file_encryption_key = session["file_encryption_key"]

        if _file_exists(os.path.basename(path)):
            raise ValueError(f"File {os.path.basename(path)} already exists")

        file_specific_key = Fernet.generate_key().decode()

        # encrypt the file with the user's file encryption key
        with open(path, "rb") as file:
            encrypted_file = password_encrypt(file.read(), file_specific_key)

        # save the encrypted file to the storage directory
        if not os.path.exists("storage"):
            os.mkdir("storage")

        with open(f"storage/{os.path.basename(path)}", "wb") as file:
            file.write(encrypted_file)

        # save the encrypted file to the files.json file
        files = _get_all_files()

        files[username].append(
            {"name": os.path.basename(path), "key": password_encrypt(file_specific_key.encode(), file_encryption_key).decode()})

        with open("files.json", "w") as file:
            json.dump(files, file)

        with open("session.json", "w") as file:
            session["files"] = files[username]
            json.dump(session, file)

    return _get_uri(os.path.basename(path), file_specific_key.encode())

def download(uri: str, path: str):
    file, key = _get_file_from_uri(uri)

    if os.path.exists(path):
        raise ValueError(f"File {path} already exists")

    if not _file_exists(file):
        raise ValueError(f"File {file} does not exist")

    with open(f"storage/{file}", "rb") as encrypted_file:
        with open(path, "wb") as file:
            file.write(password_decrypt(encrypted_file.read(), key.decode()))

    ...

@logged_in()
def delete(uri: str):
    file, key = _get_file_from_uri(uri)

    if not _file_exists(file):
        raise ValueError(f"File {file} does not exist")

    with open("session.json", "r") as session_file:
        session = json.load(session_file)
        username = session["username"]

    with open("session.json", "w") as session_file:
        files = _get_all_files()

        files[username] = [ifile for ifile in files[username] if ifile["name"] != file]

        session["files"] = files[username]
        json.dump(session, session_file)

    with open("files.json", "w") as files_file:
        if not files[username]:
            files.pop(username)
        json.dump(files, files_file)

    if json.dumps(files) == "{}":
        os.remove("files.json")

    os.remove(f"storage/{file}")

    if not os.listdir("storage"):
        os.rmdir("storage")

@logged_in()
def delete_user():
    with open("session.json", "r") as session_file:
        session = json.load(session_file)
        username = session["username"]
        files = _get_all_files()[username]

    for file in files:
        delete(_get_uri(file["name"], file["key"].encode()))

    with open("users.json", "r") as users_file:
        users = json.load(users_file)
        del users[username]

    with open("users.json", "w") as users_file:
        json.dump(users, users_file)

    if json.dumps(users) == "{}":
        os.remove("users.json")

    logout()
