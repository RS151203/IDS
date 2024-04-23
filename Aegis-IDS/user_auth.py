import sqlite3
import hashlib


def create_connection(db_file):
    try:
        conn = sqlite3.connect(db_file)
        return conn
    except sqlite3.Error as e:
        print(e)
        return None


def hash_password(password):
    return hashlib.sha256(password.encode()).hexdigest()


def execute_query(conn, query, params=()):
    try:
        with conn:
            cursor = conn.cursor()
            cursor.execute(query, params)
            return cursor
    except sqlite3.Error as e:
        print(e)
        return None


def add_user(conn, username, password):
    hashed_password = hash_password(password)
    query = "INSERT INTO user_authentication (username, password) VALUES (?, ?)"
    params = (username, hashed_password)
    if execute_query(conn, query, params):
        print("User added successfully")
    else:
        print("Failed to add user")


def check_user(conn, username, password):
    hashed_password = hash_password(password)
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT * FROM user_authentication WHERE username=? AND password=?", (username, hashed_password))
        user = cursor.fetchone()
        # return True
        if user:
            return True
        else:
            return False
    except sqlite3.Error as e:
        print(e)



def change_user_credentials(conn, current_username, current_password, new_username=None, new_password=None):
    try:
        with conn:
            cursor = conn.cursor()
            if new_username:
                query = "UPDATE user_authentication SET username=? WHERE username=? AND password=?"
                params = (new_username, current_username, hash_password(current_password))
                cursor.execute(query, params)
                current_username = new_username
            if new_password:
                hashed_new_password = hash_password(new_password)
                query = "UPDATE user_authentication SET password=? WHERE username=? AND password=?"
                params = (hashed_new_password, current_username, hash_password(current_password))
                cursor.execute(query, params)
            return current_username
    except sqlite3.Error as e:
        print(e)
        return None


def add_email(conn, username, email):
    query = "UPDATE user_authentication SET email=? WHERE username=?"
    params = (email, username)
    execute_query(conn, query, params)


def get_email(conn, username):
    try:
        cursor = conn.cursor()
        cursor.execute("SELECT email FROM user_authentication WHERE username=?", (username,))
        result = cursor.fetchone()
        if result:
            emails_text = result[0]
            return emails_text
    except sqlite3.Error as e:
        print(e)


def delete_email(conn, username):
    query = "UPDATE user_authentication SET email=NULL WHERE username=?"
    params = (username,)
    execute_query(conn, query, params)
