import os
import shutil
import pickle
from twisted.python import log

from typing import Dict, Union

DB_CONFIG = {
    'user': 'shizuka',
    'password': 'haveANiceDay', 
    'host': ' cowrie_mysql_1',
    'database': 'bakCow',
}

BASE_FS_DIR = "var/persistent_fs"  # Base directory for persistent filesystems
DEFAULT_FS_PICKLE = "/cowrie/cowrie-git/src/cowrie/data/custom.pickle"


def get_or_create_persistent_fs(username: str, password: str, ip: str, session_id: str) -> str:
    """
    Retrieve or create a persistent filesystem for a given user.
    """
    fs_dir = os.path.join(BASE_FS_DIR, f"{username}_{password}_{ip}")
    fs_path = os.path.join(fs_dir, "fs.pickle")

    if not os.path.exists(fs_dir):
        os.makedirs(fs_dir, exist_ok=True)
        shutil.copy(DEFAULT_FS_PICKLE, fs_path)
        log.msg(f"Created new persistent filesystem: {fs_path}")
    else:
        log.msg(f"Using existing persistent filesystem: {fs_path}")

    return fs_path

def save_persistent_changes(fs_path: str, changes: Dict[str, Union[str, bool]]) -> None:
    """
    Append user changes to the persistent filesystem pickle.
    """
    try:
        with open(fs_path, 'rb') as f:
            fs_data = pickle.load(f)

        fs_data.update(changes)  # Add changes to the filesystem data

        with open(fs_path, 'wb') as f:
            pickle.dump(fs_data, f)

        log.msg(f"Saved changes to persistent filesystem: {fs_path}")

    except Exception as e:
        log.msg(f"Error saving persistent changes: {e}")