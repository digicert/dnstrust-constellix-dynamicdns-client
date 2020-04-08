#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Constellix Dynamic DNS Client.

Requires Python 3.5 or later.

@see https://constellix.com/
@license MIT
"""

import argparse
import logging
import json
import requests
import typing

from pathlib import Path

from . import ddns
from . import myip
from .ip import normalise_ip_address

FMT_TABLE = 'table'
FMT_TEXT = 'text'
FMT_JSON = 'json'

EPILOG = 'Use the configuration file to securely specify defaults for all options'


def print_table(rows: typing.List[typing.List[str]]):
    column_count = 0
    column_widths = []
    for row in rows:
        column_number = 0
        if isinstance(row, dict):
            row = row.values()
        for column in row:
            column_width = min(len(str(column)), 80)
            column_number += 1
            if column_number <= column_count:
                if column_width > column_widths[column_number - 1]:
                    column_widths[column_number - 1] = column_width
            else:
                column_count += 1
                column_widths.append(column_width)
    sep = ' | '
    fmt = ''
    column_number = 0
    for column_width in column_widths:
        column_number += 1
        if column_number > 1:
            fmt += sep
        fmt += '{!s:' + str(column_width) + '} '
    printed_header = False
    for row in rows:
        if isinstance(row, dict):
            row = row.values()
        print(fmt.format(*row))
        if not printed_header:
            print('-' * min(sum(column_widths) + (len(column_widths) * len(sep)) + 1, 80))
            printed_header = True


def extra_address_family(args: dict) -> typing.Tuple[bool, bool]:
    ipv4 = args.get('4')
    ipv6 = args.get('6')
    if ipv4 == ipv6:
        ipv4 = ipv6 = True
    return ipv4, ipv6


def show_myip_providers_table(args: dict, addresses: bool = False):
    ipv4, ipv6 = extra_address_family(args)
    providers = []
    providers4 = list(myip.get_providers(myip.IPV4).keys())
    providers6 = list(myip.get_providers(myip.IPV6).keys())
    if args.get('provider') is not None:
        providers = [args.get('provider')]
    else:
        if ipv4 == ipv6:
            providers = set(providers4 + providers6)
        elif ipv4:
            providers = providers4
        elif ipv6:
            providers = providers6
    providers = sorted(providers)
    results = [
        ['Provider', 'IPv4', 'IPv6']
    ]
    column4 = lambda p: 'Disabled'
    column6 = lambda p: 'Disabled'
    if ipv4:
        if addresses:
            column4 = lambda p: myip.get_myip(provider, myip.IPV4, False)
        else:
            column4 = lambda p: str(provider in providers4)
    if ipv6:
        if addresses:
            column6 = lambda p: myip.get_myip(provider, myip.IPV6, False)
        else:
            column6 = lambda p: str(provider in providers6)
    for provider in providers:
        results.append([
            provider,
            column4(provider),
            column6(provider),
        ])
    print_table(results)


def show_myip_providers(args: dict):
    result_format = args.get('format')
    if result_format is None or result_format == FMT_TABLE:
        show_myip_providers_table(args, addresses=False)
        return
    ipv4, ipv6 = extra_address_family(args)
    results = {'ipv4': [], 'ipv6': []}
    if ipv4:
        results['ipv4'] = sorted(list(myip.get_providers(myip.IPV4).keys()))
    if ipv6:
        results['ipv6'] = sorted(list(myip.get_providers(myip.IPV6).keys()))
    if result_format == FMT_JSON:
        print(json.dumps(results, sort_keys=True, indent=4))
    else:
        providers = sorted(set(results['ipv4'] + results['ipv6']))
        for provider in providers:
            print(provider)


def show_myip(args: dict):
    result_format = args.get('format')
    if result_format is None or result_format == FMT_TABLE:
        show_myip_providers_table(args, addresses=True)
        return
    provider = args.get('provider')
    if provider is None:
        provider = myip.DEFAULT_PROVIDER
    results = {}
    ipv4, ipv6 = extra_address_family(args)
    if ipv4:
        results['ipv4'] = myip.get_myip(provider, myip.IPV4, False)
    if ipv6:
        results['ipv6'] = myip.get_myip(provider, myip.IPV6, False)
    results = {key: ip for key, ip in results.items() if ip not in ['None', 'Error', 'Unsupported']}
    if result_format == FMT_JSON:
        print(json.dumps(results, sort_keys=True, indent=4))
    else:
        for ip in results.values():
            print(ip)


def get_api(args: dict, parser: argparse.ArgumentParser) -> ddns.ConstellixAPI:
    endpoint = args.get('endpoint')
    if endpoint is None:
        endpoint = ddns.API_ENDPOINT
    key = args.get('key')
    if key is None:
        parser.error('Please provide your constellix API key')
    secret = args.get('secret')
    if secret is None:
        parser.error('Please provide your constellix API Secret key')
    api = ddns.ConstellixAPI()
    api.configure(endpoint, key, secret)
    return api


def find_api_ids(args: dict, parser: argparse.ArgumentParser, api: ddns.ConstellixAPI):
    domain_id = None
    record_ids = []

    # Handle when the ID numbers are passed in
    #  This is the fastest option because it avoids the search calls
    #  It is ok if only the domain ID is passed in
    passed_ids = args.get('id')
    if passed_ids is not None:
        if len(passed_ids) == 1:
            passed_ids = passed_ids[0].split(',')
        for value in passed_ids:
            value = value.strip()
            if domain_id is None:
                domain_id = int(value)
            else:
                record_ids.append(value)
    if domain_id is not None and len(record_ids) >= 1:
        return domain_id, record_ids

    # Handle when the hostname is passed in
    name = args.get('name')
    domain_name = None
    host_name = None
    if name is not None:
        if '.' in name:
            host_name, domain_name = name.split('.', 1)
        else:
            host_name = name

    # Search for the domain_id if we don't already have it
    if domain_id is None and domain_name is not None:
        domain_id = api.search_domain_id(domain_name)
        if domain_id is None:
            # The last search didn't work - perhaps we are
            #  trying to work with the domain apex
            domain_id = api.search_domain_id(name)
            if domain_id is not None:
                # Yup, we're at the apex!
                domain_name = name
                host_name = ''

    # Search for the record_ids
    if domain_id is not None and host_name is not None:
        for record_type in [ddns.TYPE_IPV4, ddns.TYPE_IPV6]:
            record_id = api.search_record_id(domain_id, record_type, host_name)
            if record_id is not None:
                record_ids.append(record_id)

    # Return an error if we don't have a result
    if domain_id is None and domain_name is None and host_name is None:
        parser.error('Please specify a fully qualified hostname')

    elif domain_id is None:
        parser.error('Unable to find Constellix ID for {}'.format(name))

    elif len(record_ids) <= 0:
        parser.error('Unable to find Constellix record IDs')

    else:
        return domain_id, record_ids


def show_ddns_value(args: dict, parser: argparse.ArgumentParser):
    api = get_api(args, parser)
    domain_id, record_ids = find_api_ids(args, parser, api)
    results = []
    for record_id in record_ids:
        data = api.read_record(domain_id, record_id)
        if data is not None:
            value = data['value']
            value_count = len(value)
            if value_count == 0:
                value = None
            elif value_count == 1:
                value = normalise_ip_address(value[0])
            results.append({
                'record_id': record_id,
                'name': data['name'],
                'value': value,
                'ttl': data['ttl'],
            })
    result_format = args.get('format')
    if result_format is None or result_format == FMT_TABLE:
        print("Domain ID: {!s}".format(domain_id))
        for key, value in enumerate(results):
            results[key] = [
                value['record_id'], value['name'], value['value'], value['ttl'],
            ]
        results.insert(0, ['Record ID', 'Name', 'Value', 'TTL'])
        print_table(results)
    elif result_format == FMT_JSON:
        print(json.dumps({
            'domain_id': domain_id,
            'records': results
        }, sort_keys=True, indent=4))
    else:
        for record in results:
            print(','.join([record['record_id'], record['value']]))


def get_ip_address(args: dict, ipv4: bool, ipv6: bool) -> typing.List[str]:
    results = []
    passed_ips = args.get('ip')
    if passed_ips is not None:
        if len(passed_ips) == 1:
            passed_ips = passed_ips[0].split(',')
        for ip in passed_ips:
            ip = normalise_ip_address(ip)
            if ipv4 and '.' in ip:
                results.append(ip)
            if ipv6 and ':' in ip:
                results.append(ip)
    return results


def lookup_myip_addresses_for_ddns(args: dict, ipv4: bool, ipv6: bool) -> typing.List[str]:
    provider = args.get('myip')
    if provider is None:
        provider = myip.DEFAULT_PROVIDER
    results = []
    if ipv4:
        ip = myip.get_myip(provider, myip.IPV4, False)
        if '.' in ip:
            results.append(ip)
    if ipv6:
        ip = myip.get_myip(provider, myip.IPV6, False)
        if ':' in ip:
            results.append(ip)
    return results


def update_ddns_value(args: dict, parser: argparse.ArgumentParser):
    ipv4, ipv6 = extra_address_family(args)
    api = get_api(args, parser)

    domain_id, record_ids = find_api_ids(args, parser, api)

    # Find out what types of records we have,
    #  Ideally we'll have both IPv4 and IPv6.
    got_ipv4_record = False
    got_ipv6_record = False
    for record_id in record_ids:
        record_type = api.record_type_from_id(record_id)
        if record_type == ddns.TYPE_IPV4:
            got_ipv4_record = True
        if record_type == ddns.TYPE_IPV6:
            got_ipv6_record = True

    # If only v4 or only v6 has been requested, then
    #  error if we don't we have a record of that type.
    if not (ipv4 and ipv6):
        if ipv4 and not got_ipv4_record:
            parser.error('No IPv4 records to update')
        if ipv6 and not got_ipv6_record:
            parser.error('No IPv6 records to update')

    # Disable IP types that we don't have records for
    ipv4 = ipv4 and got_ipv4_record
    ipv6 = ipv6 and got_ipv6_record

    # Complain if both types are disabled
    if not ipv4 and not ipv6:
        parser.error('No records to update')

    # Find IP address
    addresses = get_ip_address(args, ipv4, ipv6)
    if len(addresses) == 0:
        addresses = lookup_myip_addresses_for_ddns(args, ipv4, ipv6)
    if len(addresses) == 0:
        if not (ipv4 and ipv6):
            if ipv4:
                logging.error('Unable to determine IPv4 address')
            if ipv6:
                logging.error('Unable to determine IPv6 address')
        else:
            logging.error('Unable to determine IP address')
        exit(4)

    updated_ipv4_record = False
    updated_ipv6_record = False
    for record_id in record_ids:
        record_type = api.record_type_from_id(record_id)
        if record_type == ddns.TYPE_IPV4 and not ipv4:
            continue
        if record_type == ddns.TYPE_IPV6 and not ipv6:
            continue
        for ip in addresses:
            if api.record_type_from_value(ip) == record_type:
                api.update_record(domain_id, record_id, ip)
                if record_type == ddns.TYPE_IPV4:
                    updated_ipv4_record = True
                if record_type == ddns.TYPE_IPV6:
                    updated_ipv6_record = True
    if ipv4 and not updated_ipv4_record:
        logging.warning('Did not update an IPv4 record')
    if ipv6 and not updated_ipv6_record:
        logging.warning('Did not update an IPv6 record')


def read_config(args: dict) -> dict:
    #
    # Loads configuration file values into the
    #  args, so that the rest of the app sees them
    #  as default arguments.
    #
    # Note that these values are not parsed and
    #  so their validity is not checked prior to
    #  their use.
    #
    data = {}
    file = args.get('config')
    if str(file).lower()[-5:] == '.json':
        if file[0:1] == '~':
            path = Path(file)
            file = str(path.home().resolve()) + file[1:]
        path = Path(file)
        try:
            file = str(path.resolve())
            logging.debug('Loading from configuration file {}'.format(file))
            with open(file) as fh:
                data = json.load(fh)
        except IOError as exception:
            logging.debug(str(exception))
            return args
    if len(data.keys()) == 0:
        logging.warning('Unable to read config file')
        return args
    #
    # Allow the configuration to be grouped by the
    #  subparser command. So that different defaults
    #  can be specified for different commands.
    #
    # Group names are prefixed with a dot to avoid
    #  conflicts and make them easier to see.
    #
    #  e.g. {".myip": {".query": {"provider": "dnsme"}}}
    #
    groups = []
    crumbs = []
    for group in str(args.get('cmd')).split('.'):
        groups.insert(0, crumbs + [group])
        crumbs.append(group)
    groups.append(None)  # default group
    for group in groups:
        values = data
        if group is None:
            logging.debug('Loading from the default configuration group')
        else:
            logging.debug('Loading from configuration group .{}'.format('.'.join(group)))
            for key in group:
                key = '.' + key
                if key in values and isinstance(values[key], dict):
                    values = values[key]
                else:
                    group = None
                    break
            if group is None:
                continue
        for key, value in values.items():
            if isinstance(value, dict):
                continue
            if key == 'id' and args.get('name') is not None:
                continue
            if key == 'name' and args.get('id') is not None:
                continue
            if args.get(key) is None:
                args[key] = value
            if key == 'myip' and args.get('provider') is None:
                args['provider'] = value
    #
    logging.info('Loaded configuration file')
    return args


def ddns_auto(args: dict, parser: argparse.ArgumentParser):
    if args.get('config') is not None and args.get('key') is not None:
        update_ddns_value(args, parser)
    else:
        show_help(parser)


def show_help(parser: argparse.ArgumentParser):
    parser.print_help()
    parser.exit(1)


def configure_argument_parser(myip_provider_choices: list) -> argparse.ArgumentParser:
    # Global (common)
    global_common = argparse.ArgumentParser(add_help=False)
    global_common.add_argument(
        '-v', '--verbose', action='count', default=0,
        help='increase logging verbosity (use up to 3 times)'
    )
    global_common.add_argument(
        '-c', '--config', help='configuration file (default: ~/.ddns/constellix.json)',
        metavar='FILE', default='~/.ddns/constellix.json'
    )
    global_common.add_argument('-4', action='store_true', help='only IPv4')
    global_common.add_argument('-6', action='store_true', help='only IPv6')

    # Global (main parser)
    parser = argparse.ArgumentParser(
        parents=[global_common], epilog=EPILOG,
        description='Constellix Dynamic DNS Client',
    )
    parser.set_defaults(func=lambda a: ddns_auto(a, parser), cmd='')
    subparsers = parser.add_subparsers()

    # myip
    myip_subparser = subparsers.add_parser(
        'myip', epilog=EPILOG,
        help='external IP lookup',
        description='Looking up your external IP via various providers'
    )
    myip_subparser.set_defaults(func=lambda a: show_help(myip_subparser), cmd='myip')
    myip_subparsers = myip_subparser.add_subparsers()

    # myip > providers
    myip_providers_parser = myip_subparsers.add_parser(
        'providers', parents=[global_common], epilog=EPILOG,
        help='list external IP lookup providers',
        description='List of providers who will inform you of your public IP')
    myip_providers_parser.set_defaults(func=show_myip_providers, cmd='myip.providers')
    myip_providers_parser.add_argument(
        '-f', '--format', help='display format of the result',
        choices=sorted([FMT_JSON, FMT_TABLE, FMT_TEXT]))

    # myip > query
    myip_query_provider = myip_subparsers.add_parser(
        'query', parents=[global_common], epilog=EPILOG,
        help='query providers for your external IP',
        description='Query one or more providers for your public IP')
    myip_query_provider.set_defaults(func=show_myip, cmd='myip.query')
    myip_query_provider.add_argument(
        '-f', '--format', help='display format of the result',
        choices=sorted([FMT_JSON, FMT_TABLE, FMT_TEXT]))
    myip_query_provider.add_argument(
        '-p', '--provider', help='provider to query against',
        choices=myip_provider_choices)

    # ddns (common)
    ddns_common = argparse.ArgumentParser(add_help=False)
    hostname_group = ddns_common.add_argument_group(
        title='optional record identification arguments',
        description='provide full hostname, and/or the domain and record IDs'
    )
    # hostname_exclusive = hostname_group.add_mutually_exclusive_group()
    hostname_group.add_argument(
        '-n', '--name', help='fully qualified hostname')
    hostname_group.add_argument(
        '--id', nargs='*', help='domain ID followed by record ID(s)')

    api_group = ddns_common.add_argument_group(
        title='optional API arguments',
    )
    api_group.add_argument(
        '-k', '--key', help='Constellix API key'
    )
    api_group.add_argument(
        '-s', '--secret', help='Constellix API Secret key'
    )
    api_group.add_argument(
        '-e', '--endpoint', help='Contellix API Endpoint',
        default=ddns.API_ENDPOINT
    )

    # ddns (subparser)
    ddns_subparser = subparsers.add_parser(
        'ddns', parents=[], epilog=EPILOG,
        help='dynamic dns management',
        description='Constellix Dynamic DNS management')
    ddns_subparser.set_defaults(func=lambda a: ddns_auto(a, ddns_subparser), cmd='ddns')
    ddns_subparsers = ddns_subparser.add_subparsers()

    # ddns > query command
    ddns_query_parser = ddns_subparsers.add_parser(
        'query', parents=[global_common, ddns_common], epilog=EPILOG,
        help='query Constellix DNS record',
        description='Query DNS record at Constellix')
    ddns_query_parser.set_defaults(
        func=lambda a: show_ddns_value(a, ddns_update_parser),
        cmd='ddns.query'
    )
    ddns_query_parser.add_argument(
        '-f', '--format', help='display format of the result',
        choices=sorted([FMT_JSON, FMT_TABLE, FMT_TEXT]))

    # ddns > update command
    ddns_update_parser = ddns_subparsers.add_parser(
        'update', parents=[global_common, ddns_common], epilog=EPILOG,
        help='update Constellix DNS record',
        description='Update DNS record at Constellix')
    ddns_update_parser.set_defaults(
        func=lambda a: update_ddns_value(a, ddns_update_parser),
        cmd='ddns.update'
    )

    value_group = ddns_update_parser.add_argument_group(
        title='optional value arguments',
        description='the value to update the record with'
    )
    value_group.add_argument(
        '--ip', help='IP addresses', nargs='*'
    )
    value_group.add_argument(
        '--myip', help='use value from specified provider',
        choices=myip_provider_choices)

    return parser


def configure_logging(verbosity=0):
    if not isinstance(verbosity, int):
        verbosity = 3  # DEBUG
    level = 40 - (10 * verbosity)
    if level < logging.DEBUG:
        level = logging.DEBUG
    logging.basicConfig(
        format='%(levelname)-8s - %(message)s',
        level=level
    )
    logger = logging.getLogger()
    if logger.level != level:
        logger.setLevel(level)
        logging.debug('Switched logging level to {}'.format(
            logging.getLevelName(level))
        )


def main():
    try:
        configure_logging()

        # parse cli arguments
        myip_provider_choices = sorted(list(myip.get_providers(None).keys()))
        parser = configure_argument_parser(myip_provider_choices)
        args = parser.parse_args()

        # allow verbosity to be set before reading config file
        if args.verbose > 0:
            configure_logging(args.verbose)

        # read the configuration file
        values = vars(args)
        values = read_config(values)

        # allow verbosity to be controlled via config file
        if values.get('verbose') > 0:
            configure_logging(values.get('verbose'))

        # dispatch to the arguments selected function
        args.func(values)

    except requests.exceptions.HTTPError:
        logging.error('Fatal error during API communication')

    except KeyboardInterrupt:
        exit(3)  # ignore the exception and exit


if __name__ == '__main__':
    main()
