"""Errors shared by the admin service and its transports."""


class AdminError(Exception):
    """An error meant to be shown to the admin (bad device id, etc.)."""
