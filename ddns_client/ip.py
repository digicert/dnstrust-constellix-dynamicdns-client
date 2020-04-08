# -*- coding: utf-8 -*-

"""
Constellix Dynamic DNS Client.

Requires Python 3.5 or later.

@see https://constellix.com/
@license MIT
"""

import ipaddress


def normalise_ip_address(ip: str):
    return ipaddress.ip_address(ip).compressed
