import os
import mysql.connector
from datetime import datetime
from typing import Optional

DB_CONFIG = {
    'user': 'shizuka',
    'password': 'haveANiceDay', 
    'host': ' cowrie_mysql_1',
    'database': 'bakCow',
}

BASE_FS_DIR = "var/persistent_fs"  # Base directory for persistent filesystems


def get_or_create_persistent_fs(username: str, password: str, ip_address: str, session_id: str) -> Optional[str]:
    """
    Retrieve or create a persistent filesystem path for a hacker.
    """
    fs_path = None

    try:
        # Connect to the database
        conn = mysql.connector.connect(**DB_CONFIG)
        cursor = conn.cursor(dictionary=True)

        # Check if filesystem already exists
        cursor.execute("""
            SELECT fs_path FROM persistent_filesystem
            WHERE username=%s AND password=%s AND ip_address=%s
        """, (username, password, ip_address))

        result = cursor.fetchone()
        print(f"Query result: {result}")

        if result:
            fs_path = result['fs_path']
            print(f"Using existing fs_path: {fs_path}")
        else:
            # Generate new filesystem path
            fs_dir_name = f"{username}_{ip_address}_{session_id}"
            fs_path = os.path.join(BASE_FS_DIR, fs_dir_name)
            os.makedirs(fs_path, exist_ok=True)
            print(f"Created new fs_path: {fs_path}")

            # Insert into database
            cursor.execute("""
                INSERT INTO persistent_filesystem 
                (session_id, username, password, ip_address, fs_path, created_at)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (session_id, username, password, ip_address, fs_path, datetime.now()))

            conn.commit()
            print("New fs_path committed to DB.")

    except Exception as e:
        print(f"Error: {e}")
    finally:
        cursor.close()
        conn.close()

    return fs_path