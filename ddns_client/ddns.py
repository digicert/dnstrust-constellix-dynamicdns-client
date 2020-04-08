# -*- coding: utf-8 -*-

"""
Constellix Dynamic DNS Client.

Requires Python 3.5 or later.

@see https://constellix.com/
@license MIT
"""

import base64
import hashlib
import hmac
import logging
import requests
import time
import typing

from .ip import normalise_ip_address

TYPE_IPV4 = 'A'
TYPE_IPV6 = 'AAAA'

API_ENDPOINT = 'api.dns.constellix.com'

ENCODING = 'UTF-8'


class ConstellixAPI:
    endpoint = API_ENDPOINT
    key = None
    secret = None
    session = None
    first = True

    def log_first_call(self):
        if self.first:
            logging.info('Connecting to Constellix API')
            self.first = False

    def configure(self, endpoint: str, key: str, secret: str):
        self.endpoint = endpoint or API_ENDPOINT
        self.key = key
        self.secret = secret
        self.session = requests.Session()
        self.session.headers.update({
            'Content-Type': 'application/json',
            'x-cns-security-token': self.security_token()
        })
        self.first = True

    def security_token(self):
        message = str(int(time.time() * 1000))
        return ':'.join([
            self.key,
            base64.b64encode(
                hmac.new(
                    bytes(self.secret, ENCODING),
                    bytes(message, ENCODING),
                    hashlib.sha1
                ).digest()
            ).decode(ENCODING),
            message
        ])

    def url(self, pattern, *args):
        if pattern[0] != '/':
            pattern = '/' + pattern
        return 'https://' + self.endpoint + pattern.format(*args)

    # noinspection PyMethodMayBeStatic
    def log_api_errors(self, context, response):
        if response.status_code >= 300:
            logging.debug(response.text)
        # noinspection PyBroadException
        try:
            data = response.json()
            if 'errors' in data:
                for error in data['errors']:
                    logging.error(context + ': ' + error)
        except Exception:
            pass  # ignore exceptions in this logging code

    def search_query(self, url: str):
        self.log_first_call()
        response = self.session.get(url)
        if response.status_code >= 500 or response.status_code == 401:
            self.log_api_errors('search', response)
            response.raise_for_status()
        data = response.json()
        if 'errors' in data:
            logging.debug(data['errors'])
            return None
        if len(data) == 0:
            return None
        data = data.pop()
        return data['id']

    def search_domain_id(self, name: str):
        domain_id = self.search_query(self.url(
            '/v1/domains/search?exact={}',
            name
        ))
        if domain_id is None:
            logging.warning('Domain {} not found'.format(name))
            return None
        logging.info('Domain {} has ID {}'.format(name, domain_id))
        return domain_id

    def search_record_id(self, domain_id, record_type: str, name: str):
        record_id = self.search_query(self.url(
            '/v1/domains/{}/records/{}/search?exact={}',
            domain_id, record_type, name
        ))
        if record_id is None:
            logging.warning('Domain {} Host {} {} record not found'.format(
                domain_id, name, record_type
            ))
            return None
        record_id = '{!s}:{!s}'.format(record_type, record_id)
        logging.info('Domain {} Host {} {} record has ID {}'.format(
            domain_id, name, record_type, record_id
        ))
        return record_id

    def read_domain(self, domain_id):
        self.log_first_call()
        response = self.session.get(self.url(
            '/v1/domains/{}',
            domain_id
        ))
        self.log_api_errors('domain {}'.format(domain_id), response)
        response.raise_for_status()
        data = response.json()
        return data

    def create_record(self, domain_id, record_type, name, value):
        raise NotImplementedError()

    def read_record(self, domain_id, record_id: str):
        record_type, record_id = self.parse_record_id(record_id)
        self.log_first_call()
        response = self.session.get(self.url(
            '/v1/domains/{}/records/{}/{}',
            domain_id, record_type, record_id
        ))
        self.log_api_errors(
            'domain {} record {}'.format(domain_id, record_id),
            response
        )
        response.raise_for_status()
        data = response.json()
        return data

    def update_record(self, domain_id, record_id: str, value):
        value = normalise_ip_address(value)
        logging.info('Updating domain {} record {} to value {}'.format(
            domain_id, record_id, value
        ))
        data = self.read_record(domain_id, record_id)
        record_type, record_id_int = self.parse_record_id(record_id)

        # The API won't allow us to set value to it's current value
        for ip in data['value']:
            if value == normalise_ip_address(ip):
                logging.info(
                    'Domain {} record {} is already set to the requested value'.format(
                        domain_id, record_id
                    )
                )
                return None

        # These are the minimum needed fields,
        #  Although I'm augmenting a downloaded copy just to be safe.
        #  Currently it's necessary to set the value in two places.
        data['id'] = int(record_id_int)
        data['modifiedTs'] = int(time.time() * 1000)
        data['ttl'] = int(data['ttl'])
        data['value'] = [value]
        data['roundRobin'][0]['value'] = value  # [{'disableFlag': False, 'value': value}]

        response = self.session.put(
            self.url(
                '/v1/domains/{}/records/{}/{}',
                domain_id, record_type, record_id_int
            ),
            json=data
        )
        self.log_api_errors(
            'domain {} record {}'.format(domain_id, record_id),
            response
        )
        response.raise_for_status()
        data = response.json()
        if 'success' in data:
            logging.info('Domain {} record {} updated successfully'.format(
                domain_id, record_id
            ))
        return data

    def record_type_from_id(self, record_id: str):
        record_type, record_id = self.parse_record_id(record_id)
        return record_type

    @staticmethod
    def parse_record_id(record_id: str) -> typing.Union[typing.Tuple[str, str], typing.Tuple[None, None]]:
        values = record_id.split(':')
        if len(values) == 2:
            return values[0], values[1]
        return None, None

    @staticmethod
    def record_type_from_value(ip: str) -> str:
        if ':' in normalise_ip_address(ip):
            return TYPE_IPV6
        else:
            return TYPE_IPV4
