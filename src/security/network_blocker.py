"""
Network Blocker - Prevents all network access for security

This module ensures that the application cannot make any network requests,
protecting user privacy by keeping all data local.

Security Rationale:
- Blocks socket creation to prevent data leaks
- Monitors network attempts for security logging
- Ensures truly offline operation
"""

import socket
import logging
from typing import Any, Callable
from unittest.mock import patch


class NetworkBlocker:
    """
    Blocks all network access for the application.

    Security: Prevents accidental or malicious data transmission by
    completely disabling network socket creation.
    """

    def __init__(self):
        self.logger = logging.getLogger(__name__)
        self._original_socket = socket.socket
        self._is_blocked = False

    def block_network_access(self) -> None:
        """
        Block all network socket creation.

        Security: Replaces socket creation with a blocking function
        that logs attempts and raises exceptions.
        """
        if self._is_blocked:
            return

        def blocked_socket(*args, **kwargs):
            """Replacement socket function that blocks creation."""
            self.logger.warning(
                f"Network access attempt blocked: args={args}, kwargs={kwargs}"
            )
            raise ConnectionError("Network access is blocked for security reasons")

        # Monkey patch socket creation
        socket.socket = blocked_socket
        self._is_blocked = True
        self.logger.info("Network access has been blocked")

    def restore_network_access(self) -> None:
        """
        Restore network access (for testing purposes only).

        Security: Should only be used in test environments.
        """
        if not self._is_blocked:
            return

        socket.socket = self._original_socket
        self._is_blocked = False
        self.logger.warning("Network access has been restored")

    def is_blocked(self) -> bool:
        """
        Check if network access is currently blocked.

        Returns:
            bool: True if network access is blocked
        """
        return self._is_blocked

    def test_network_blocking(self) -> bool:
        """
        Test that network blocking is working properly.

        Returns:
            bool: True if network is properly blocked
        """
        if not self._is_blocked:
            return False

        try:
            # This should fail if blocking is working
            test_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            test_socket.close()
            return False
        except ConnectionError as e:
            if "blocked for security reasons" in str(e):
                return True
            return False
        except Exception:
            return False


# Global instance for application-wide use
network_blocker = NetworkBlocker()
