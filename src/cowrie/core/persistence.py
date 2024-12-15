import os
import mysql.connector
from datetime import datetime
import shutil


DB_CONFIG = {
    'user': 'shizuka',
    'password': 'haveANiceDay', 
    'host': ' cowrie_mysql_1',
    'database': 'bakCow',
}

BASE_FS_DIR = "var/persistent_fs"  # Base directory for persistent filesystems
DEFAULT_FS_PICKLE = "/cowrie/cowrie-git/fs.pickle"


def get_or_create_persistent_fs(username, password, ip_address, session_id):
    """
    Generate or retrieve a unique persistent shell directory for a hacker.
    """
    conn = mysql.connector.connect(**DB_CONFIG)
    cursor = conn.cursor(dictionary=True)

    try:
        # Check if entry already exists
        cursor.execute("""
            SELECT fs_path FROM persistent_filesystem
            WHERE username=%s AND password=%s AND ip_address=%s
        """, (username, password, ip_address))
        result = cursor.fetchone()

        if result:
            fs_path = result['fs_path']
        else:
            # Generate a new persistent directory name
            fs_dir_name = f"{username}_{ip_address}_{session_id}"
            fs_path = os.path.join("persistent", fs_dir_name)

            # Create the persistent directory
            full_path = os.path.join(BASE_FS_DIR, fs_path)
            os.makedirs(full_path, exist_ok=True)

            # Copy default fs.pickle to the new directory
            fs_pickle_dest = os.path.join(full_path, "fs.pickle")
            if not os.path.exists(fs_pickle_dest):
                shutil.copy(DEFAULT_FS_PICKLE, fs_pickle_dest)

            # Insert the persistent FS path into the database
            cursor.execute("""
                INSERT INTO persistent_filesystem (session_id, username, password, ip_address, fs_path, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session_id, username, password, ip_address, fs_path, datetime.now()))
            conn.commit()

        return fs_path

    finally:
        cursor.close()
        conn.close()