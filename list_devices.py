import os
import csv
import time
import sys
import json
import logging
import argparse
import coloredlogs
from fmc_rest import FMCRest

from requests.exceptions import HTTPError

DEFAULTS = {
            'outfile': './output.csv',
            'result_limit': 25,
            'retry_timer': 60
            }

def _format(json_obj):
    return json.dumps(json_obj, sort_keys=True, indent=2, separators=(',', ': '))


def init():
    '''
        init()
        Handle command line args, setup log, etc..
    '''

    global DEFAULTS

    # Configure logging
    coloredlogs.install(level='DEBUG',
                        fmt='%(asctime)s %(levelname)s %(message)s')

    # Supress requests log
    logging.getLogger('requests').setLevel(logging.WARNING)
    logging.getLogger('urllib3').setLevel(logging.WARNING)

    # Handle command line args
    parser = argparse.ArgumentParser(description='List all FMC managed FTD devices')
    parser.add_argument('-f, --fmc', dest='hostname',
                        help = 'FMC Hostname or IP (in the format hostname:port). Alternatively, use the FMC_HOSTNAME env var.',
                        default = None)
    parser.add_argument('-u, --user', dest='username',
                        help = 'FMC API username (Please use FMC_USERNAME env var instead)',
                        default = None)
    parser.add_argument('-p, --password', dest='password',
                        help = 'FMC API password (Please use FMC_PASSWORD env var instead)',
                        default = None)
    parser.add_argument('-o, --outfile', dest="outfile",
                        help = f"CSV output filename (Default: {DEFAULTS['outfile']})",
                        default=DEFAULTS['outfile'])
    parser.add_argument('-D, --debug', dest='debug',
                        help = 'Full debug output',
                        action = 'store_true')
    parser.add_argument('-l, --limit', dest='result_limit',
                        help = f"Pagination limit (Default: {DEFAULTS['result_limit']})",
                        default=DEFAULTS['result_limit'])
    parser.add_argument('-r, --retry', dest='retry_timer',
                        help = f"Wait in secs for retry after rate limit hit (Default: {DEFAULTS['retry_timer']})",
                        default=DEFAULTS['retry_timer'])


    options = parser.parse_args()

    # Enable debug
    if not options.debug:
        coloredlogs.decrease_verbosity()

    # Load from env if not provided on the command line
    if options.hostname is None:
        options.hostname = os.environ.get('FMC_HOSTNAME')
        logging.debug('Loading hostname from environment')
    if options.username is None:
        options.username = os.environ.get('FMC_USERNAME')
        logging.debug('Loading username from environment')
    if options.password is None:
        options.password = os.environ.get('FMC_PASSWORD')
        logging.debug('Loading password from environment')

    if options.hostname is None:
        logging.fatal('No fmc hostname provided')
        sys.exit(3)
    if options.username is None:
        logging.fatal('No username provided')
        sys.exit(5)
    if options.password is None:
        logging.fatal('No password provided')
        sys.exit(7)

    # Strip off 'https://' from the hostname if it is provided
    # ...took me way too long to realize this was my problem :)
    if str(options.hostname).startswith('https://'):
        options.hostname = str(options.hostname).replace('https://', '', 1)

    return options


def main(options):
    ''' Let's make do stuff
    '''

    # Connect to the FMC RestAPI
    start = time.time()
    logging.info(f'Connecting to FMC... ({options.hostname})')
    fmc = FMCRest(options.hostname, options.username, options.password)
    logging.debug(f"Connected. Session ({fmc.session.headers['X-auth-access-token']})")
    elapsed = time.time() - start
    logging.info('Time elapsed for session establishment: %1.1f secs', elapsed)


    # Grab the list of AC policies on the FMC
    start = time.time()
    logging.info("Loading devices list from FMC")
    devices = getDeviceList(fmc, options)
    logging.info('Time elapsed loading devices list from FMC: %1.1f secs', elapsed)


    start = time.time()
    logging.info(f"Loading devices details from FMC for {len(devices)} devices")
    lines = []
    cleanup = []
    for dev in devices:
        while True:
            try:
                device = getDevice(fmc, dev['id'])
                logging.debug("JSON:\n" + _format(device))
                lines.append(device)
                break
            except HTTPError as e:
                if e.response.status_code == 429:
                    logging.error(f"Rate Limit Hit : backing off {options.retry_timer} secs")
                    time.sleep(options.retry_timer)

    if len(lines) == 0:
        logging.fatal("No registered devices detected")
        exit(1)
    logging.info(f"Loaded {len(lines)} devices")
    elapsed = time.time() - start
    logging.info('Time elapsed loading device details from FMC: %1.1f secs', elapsed)


    # Output CSV file
    start = time.time()
    logging.info(f"Writing devices to CSV file ({options.outfile})")
    fields = list(lines[0].keys())
    fields.sort()
    with open(options.outfile, 'w') as csvfile:
        writer = csv.DictWriter(csvfile, fieldnames=fields, extrasaction='ignore')
        writer.writeheader()
        writer.writerows(lines)

    elapsed = time.time() - start
    logging.info('Time elapsed for writing CSV file: %1.1f secs', elapsed)


def getDeviceList(fmc, options):
    offset = 0
    rval = []
    done = False

    # Unspool the pagination
    while True:
        resp = fmc.get(f"/devices/devicerecords?offset={offset}&limit={options.result_limit}")
        logging.debug(_format(resp))
        rval = rval + resp['items']
        if 'paging' not in resp or 'next' not in resp['paging']:
            break
        else:
            offset += options.result_limit

    return rval

def getDevice(fmc,id):
    device = fmc.get(f"/devices/devicerecords/{id}")

    # Flatten the device record for CSV output
    if 'accessPolicy' in device:
        device['accessPolicy'] = device['accessPolicy']['name']
    if 'healthPolicy' in device:
        device['healthPolicy'] = device['healthPolicy']['name']
    if 'license_caps' in device:
        device['license_caps'] = ' | '.join(device['license_caps'])
    if 'deviceGroup' in device:
        device['deviceGroup'] = device['deviceGroup']['name']
    else:
        device['deviceGroup'] = "None"

    # Grab some of the meta-data and flatten it
    if 'metadata' in device:
        if 'clusterBootstrapSupported' in device['metadata']:
            device['clusterBootstrapSupported'] = device['metadata']['clusterBootstrapSupported']
        if 'deviceSerialNumber' in device['metadata']:
            device['deviceSerialNumber'] = device['metadata']['deviceSerialNumber']
        if 'isMultiInstance' in device['metadata']:
            device['isMultiInstance'] = device['metadata']['isMultiInstance']
        if 'lspVersion' in device['metadata']:
            device['lspVersion'] = device['metadata']['lspVersion']
        if 'snortVersion' in device['metadata']:
            device['snortVersion'] = device['metadata']['snortVersion']
        if 'vdbVersion' in device['metadata']:
            device['vdbVersion'] = device['metadata']['vdbVersion']
        if 'inventoryData' in device['metadata']:
            if 'cpuCores' in device['metadata']['inventoryData']:
                device['cpuCores'] = device['metadata']['inventoryData']['cpuCores']
            if 'cpuType' in device['metadata']['inventoryData']:
                device['cpuType'] = device['metadata']['inventoryData']['cpuType']
            if 'memoryInMB' in device['metadata']['inventoryData']:
                device['memoryInMB'] = device['metadata']['inventoryData']['memoryInMB']       

    # Delete fields
    if 'advanced' in device:
        del device['advanced']
    if 'metadata' in device:
        del device['metadata']
    if 'links' in device:
        del device['links']
    if 'isFWaaS' in device:
        del device['isFWaaS']

    return device


if __name__ == '__main__':
    main(init())
