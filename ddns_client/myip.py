# -*- coding: utf-8 -*-

"""
Constellix Dynamic DNS Client.

Requires Python 3.5 or later.

@see https://constellix.com/
@license MIT
"""

import logging
import typing
import requests

from .ip import normalise_ip_address

IPV4 = 'IPv4'
IPV6 = 'IPv6'

FMT_TEXT = 'text'
FMT_JSON = 'json'

DEFAULT_PROVIDER = 'constellix'

PROVIDERS_IPV4 = {
    'constellix': {
        'url': 'https://myip4.constellix.com/?format=json',
        'format': FMT_JSON,
        'key': 'ip'
    },
    'dnsme': {
        'url': 'http://myip.dnsmadeeasy.com/',
        'format': FMT_TEXT
    },
    'httpbin': {
        'url': 'https://httpbin.org/ip',
        'format': FMT_JSON,
        'key': 'origin'
    },
    'ipify': {
        'url': 'https://api.ipify.org?format=json',
        'format': FMT_JSON,
        'key': 'ip'
    },
    'ipinfo': {
        'url': 'https://ipinfo.io',
        'format': FMT_JSON,
        'key': 'ip'
    }
}

PROVIDERS_IPV6 = {
    'constellix': {
        'url': 'https://myip6.constellix.com?format=json',
        'format': FMT_JSON,
        'key': 'ip'
    },
    'ipify': {
        # This URL is actually dual stack, so you only get
        #  an IPv6 result if you use IPv6 to connect to it.
        'url': 'https://api6.ipify.org?format=json',
        'format': FMT_JSON,
        'key': 'ip'
    },
}


class UnknownAddressFamily(Exception):
    pass


class UnknownMyIpProvider(Exception):
    pass


class InvalidIPAddress(Exception):
    pass


class UnknownIpLookupError(Exception):
    pass


def get_providers(address_family: typing.Optional[str] = None) -> typing.Dict[str, typing.Dict[str, str]]:
    if address_family is None:
        return {**PROVIDERS_IPV4, **PROVIDERS_IPV6}
    if address_family == IPV4:
        return PROVIDERS_IPV4
    elif address_family == IPV6:
        return PROVIDERS_IPV6
    else:
        raise UnknownAddressFamily('Unknown address family {}'.format(address_family))


def get_myip(provider: str, address_family: str, raise_on_error: bool = True) -> str:
    # noinspection PyBroadException
    try:
        providers = get_providers(address_family)
        if provider not in providers:
            if not raise_on_error:
                return 'Unsupported'
            raise UnknownMyIpProvider('Unknown {} address provider {}'.format(address_family, provider))
        logging.info('Attempting to find {} address via {}'.format(address_family, provider))
        response = requests.get(providers[provider].get('url'))
        response.raise_for_status()
        if providers[provider].get('format') == FMT_JSON:
            json = response.json()
            assert (isinstance(json, dict))
            ip = json.get(providers[provider].get('key'))
        else:
            ip = response.text.strip()
        ip = normalise_ip_address(ip)
        if (address_family == IPV4 and '.' not in ip) or (address_family == IPV6 and ':' not in ip):
            raise InvalidIPAddress('Invalid {} address returned by {}'.format(address_family, provider))
        logging.info('Discovered {} address {} via {}'.format(address_family, ip, provider))
        return ip
    except Exception as exception:
        if not raise_on_error:
            return 'Error'
        raise UnknownIpLookupError() from exception
