# Copyright (c) 2009-2014 Upi Tamminen <desaster@gmail.com>
# See the COPYRIGHT file for more information

"""
This module contains ...
"""


from __future__ import annotations

from typing import Literal

from twisted.conch.ssh import session
from twisted.conch.ssh.common import getNS
from twisted.python import log
from cowrie.core.persistence import get_or_create_persistent_fs
import os
from datetime import datetime


class HoneyPotSSHSession(session.SSHSession):
    """
    This is an SSH channel that's used for SSH sessions
    """

    def __init__(self, *args, **kw):
        session.SSHSession.__init__(self, *args, **kw)
        self.persistent_fs_path = None  # Initialize fs path as None

    def setup_persistent_filesystem(self) -> None:
        """
        Retrieve or create a persistent filesystem for this session.
        """
        try:
            # Extract session information after transport is initialized
            session_id = self.conn.transport.transport.sessionno
            ip_address = self.conn.transport.transport.getPeer().host
            username = self.conn.transport.factory.username
            password = self.conn.transport.factory.password

            # Retrieve persistent fs path
            self.persistent_fs_path = get_or_create_persistent_fs(
                username, password, ip_address, session_id
            )
            log.msg(f"Persistent filesystem path set: {self.persistent_fs_path}")

            # Set environment variable for shell
            if self.session:
                self.session.environ['PERSISTENT_FS'] = self.persistent_fs_path
        except Exception as e:
            log.err(f"Error setting up persistent filesystem: {e}")

    def request_env(self, data: bytes) -> Literal[0, 1]:
        self.setup_persistent_filesystem()


        name, rest = getNS(data)
        value, rest = getNS(rest)

        if rest:
            log.msg(f"Extra data in request_env: {rest!r}")
            return 1

        log.msg(
            eventid="cowrie.client.var",
            format="request_env: %(name)s=%(value)s",
            name=name.decode("utf-8"),
            value=value.decode("utf-8"),
        )
        # FIXME: This only works for shell, not for exec command
        if self.session:
            self.session.environ[name.decode("utf-8")] = value.decode("utf-8")
        return 0

    def request_agent(self, data: bytes) -> int:
        log.msg(f"request_agent: {data!r}")
        return 0

    def request_x11_req(self, data: bytes) -> int:
        log.msg(f"request_x11: {data!r}")
        return 0

    def closed(self) -> None:
        """
        This is reliably called on session close/disconnect and calls the avatar
        """
        session.SSHSession.closed(self)
        self.client = None

    def eofReceived(self) -> None:
        """
        Redirect EOF to emulated shell. If shell is gone, then disconnect
        """
        if self.session:
            self.session.eofReceived()
        else:
            self.loseConnection()

    def sendEOF(self) -> None:
        """
        Utility function to request to send EOF for this session
        """
        self.conn.sendEOF(self)

    def sendClose(self) -> None:
        """
        Utility function to request to send close for this session
        """
        self.conn.sendClose(self)

    def channelClosed(self) -> None:
        log.msg("Called channelClosed in SSHSession")
