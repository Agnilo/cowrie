# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains authentication code
"""

from __future__ import annotations

import configparser
import json
import re
from collections import OrderedDict
from os import path
from random import randint
from typing import Any
from re import Pattern
import uuid
from datetime import datetime

import mysql.connector
from mysql.connector import Error
from twisted.python import log

from cowrie.core.config import CowrieConfig
from cowrie.shell.protocol import HoneyPotBaseProtocol

_USERDB_DEFAULTS: list[str] = [
    "root:x:!root",
    "root:x:!123456",
    "root:x:!/honeypot/i",
    "root:x:*",
    "phil:x:*",
    "phil:x:fout",
]


class UserDB:
    """
    By Walter de Jong <walter@sara.nl>
    """

    protocol_map = {}

    def __init__(self) -> None:
        self.userdb: dict[
            tuple[Pattern[bytes] | bytes, Pattern[bytes] | bytes], bool
        ] = OrderedDict()
        self.db = self.connect_to_db()
        self.load()

    def connect_to_db(self):
        try:
            connection = mysql.connector.connect(
                host="cowrie_mysql_1",
                user="shizuka",
                password="haveANiceDay",
                database="bakCow"
            )
            if connection.is_connected():
                log.msg("Connected to MySQL database")
            return connection
        except Error as e:
            log.msg(f"MySQL connection error: {e}")
            return None

    def load(self) -> None:
        """
        load the user db
        """

        dblines: list[str]

        userdb_path = "{}/userdb.txt".format(CowrieConfig.get("honeypot", "etc_path"))

        log.msg(f"Attempting to read user database from: {userdb_path}")
        
        # try:
        #     with open(
        #         "{}/userdb.txt".format(CowrieConfig.get("honeypot", "etc_path")),
        #         encoding="ascii",
        #     ) as db:
        #         dblines = db.readlines()
        # except OSError:
        #     log.msg("Could not read etc/userdb.txt, default database activated")
        #     dblines = _USERDB_DEFAULTS
        try:
            with open(userdb_path, encoding="ascii") as db:
                dblines = db.readlines()
        except OSError as e:
            log.msg(f"Could not read {userdb_path}, error: {e}")
            dblines = _USERDB_DEFAULTS

        for user in dblines:
            if not user.startswith("#"):
                try:
                    login = user.split(":")[0].encode("utf8")
                    password = user.split(":")[2].strip().encode("utf8")
                except IndexError:
                    continue
                else:
                    self.adduser(login, password)

    def checklogin(
        self, thelogin: bytes, thepasswd: bytes, src_ip: str = "0.0.0.0", session_id=None
    ) -> bool:
        
        success = False
        username = thelogin.decode("utf8")
        password = thepasswd.decode("utf8")

        if session_id is None:
            log.msg("Session ID not provided during checklogin")
        else:
            log.msg(f"Session ID during checklogin: {session_id}")

        log.msg(f"session_id in auth.py: {session_id}")

        for credentials, policy in self.userdb.items():
            login, passwd = credentials
            if self.match_rule(login, thelogin) and self.match_rule(passwd, thepasswd):
                success = True
                self.replay_commands(username, password, src_ip, session_id)
                break  # Exit the loop once a match is found

        # Log the login attempt once based on the result
        self.log_login_attempt(username, password, src_ip, success, session_id)
        return success
    
    def log_login_attempt(self, username: str, password: str, ip: str, success: bool, session_id: str) -> None:
        """
        Log login attempts to the database.
        """
        #session_id = str(uuid.uuid4()).replace("-", "")  # Generate a new session ID
        
        timestamp = datetime.now()

        query = """
        INSERT INTO auth (session, success, username, password, ip, timestamp)
        VALUES (%s, %s, %s, %s, %s, %s)
        """
        params = (session_id, int(success), username, password, ip, timestamp)

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            self.db.commit()
            cursor.close()
            log.msg(f"Login attempt logged for {username} at IP {ip} with success: {success}")
        except Error as e:
            log.msg(f"MySQL error during login logging: {e}")

    def replay_commands(self, username: str, password: str, ip: str, session_id: str) -> None:
        """
        Replay previously executed commands for returning attackers.
        """

        session_id = session_id.strip().lower()

        query = """
            SELECT DISTINCT i.input, i.timestamp
            FROM auth a
            INNER JOIN input i ON i.session = a.session
            INNER JOIN sessions s ON s.id = a.session
            WHERE a.success = 1 AND i.success = 1 
            AND a.username = %s AND a.password = %s 
            AND s.ip = %s
            AND i.input NOT LIKE '%ping%' 
            AND i.input NOT LIKE '%exit%' 
            AND i.input NOT LIKE '%ls%' 
            AND i.input NOT LIKE '%curl%' 
            AND i.input NOT LIKE '%wget%'
            ORDER BY i.timestamp ASC;
        """
        params = (username, password, ip)

        #log.msg(f"Current protocol_map: {UserDB.protocol_map}")
        #log.msg(f"Trying to find protocol for session_id: {session_id}")

        try:
            cursor = self.db.cursor()
            cursor.execute(query, params)
            past_commands = cursor.fetchall()
            cursor.close()

            if not past_commands:
                log.msg(f"No past commands found for {username}@{ip}.")
                return

            log.msg(f"Found {len(past_commands)} commands to replay for {username}@{ip}.")

            #protocol = self.protocol_map.get(session_id)
            protocol = UserDB.protocol_map.get(session_id)
            if not protocol or not hasattr(protocol, "cmdstack"):
                log.msg(f"No valid protocol object found for session {session_id}")
                #log.msg(f"Protocol map keys: {list(UserDB.protocol_map.keys())}")
                #log.msg(f"Requested session_id: {session_id}")
                return

            for command in past_commands:
                log.msg(f"Replaying command for {username}@{ip}: {command[0]}")
                protocol.cmdstack[-1].lineReceived(command[0].encode())

        except Error as e:
            log.msg(f"MySQL error during command replay: {e}")

    def match_rule(self, rule: bytes | Pattern[bytes], data: bytes) -> bool | bytes:
        if isinstance(rule, bytes):
            return rule in [b"*", data]
        return bool(rule.search(data))

    def re_or_bytes(self, rule: bytes) -> Pattern[bytes] | bytes:
        """
        Convert a /.../ type rule to a regex, otherwise return the string as-is

        @param login: rule
        @type login: bytes
        """
        res = re.match(rb"/(.+)/(i)?$", rule)
        if res:
            return re.compile(res.group(1), re.IGNORECASE if res.group(2) else 0)

        return rule

    def adduser(self, login: bytes, passwd: bytes) -> None:
        """
        All arguments are bytes

        @param login: user id
        @type login: bytes
        @param passwd: password
        @type passwd: bytes
        """
        user = self.re_or_bytes(login)

        if passwd[0] == ord("!"):
            policy = False
            passwd = passwd[1:]
        else:
            policy = True

        p = self.re_or_bytes(passwd)
        self.userdb[(user, p)] = policy
