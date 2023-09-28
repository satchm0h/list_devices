# list_devices.py

Simple Python 3 script to dump the list of managed devices from Cisco Secure Firewall Management Center (FMC) to a CSV file

## Installation

Note: Only tested on linux with python3.8 and python 3.10

- Check out this repo: `git clone git@github.com:satchm0h/device_list.git`
- `cd` into the `device_list` directory
- Run `python3 -m venv venv` to create a virtual environment
- Run `source venv/bin/activate` to activate the virtual environment
- Run `pip3 install -r requirements.txt` to install library dependencies

## Usage

    λ  python3 list_devices.py -h

    usage: list_devices.py [-h] [-f, --fmc HOSTNAME] [-u, --user USERNAME] [-p, --password PASSWORD] [-o, --outfile OUTFILE] [-D, --debug]
                          [-l, --limit RESULT_LIMIT] [-r, --retry RETRY_TIMER]

    List all FMC managed FTD devices

    options:
      -h, --help            show this help message and exit
      -f, --fmc HOSTNAME    FMC Hostname or IP (in the format hostname:port). Alternatively, use the FMC_HOSTNAME env var.
      -u, --user USERNAME   FMC API username (Please use FMC_USERNAME env var instead)
      -p, --password PASSWORD
                            FMC API password (Please use FMC_PASSWORD env var instead)
      -o, --outfile OUTFILE
                            CSV output filename (Default: ./output.csv)
      -D, --debug           Full debug output
      -l, --limit RESULT_LIMIT
                            Pagination limit (Default: 25)
      -r, --retry RETRY_TIMER
                            Wait in secs for retry after rate limit hit (Default: 60)

## Example Output

### CLI output

    λ  python3 list_devices.py -f HOSTNAME -u USERNAME -p PASSWORD
    2023-09-28 20:40:30 INFO Connecting to FMC... (HOSTNAME)
    2023-09-28 20:40:32 INFO Time elapsed for session establishment: 2.5 secs
    2023-09-28 20:40:32 INFO Loading devices list from FMC
    2023-09-28 20:40:36 INFO Time elapsed loading devices list from FMC: 2.5 secs
    2023-09-28 20:40:36 INFO Loading devices details from FMC for 200 devices
    2023-09-28 20:41:00 WARNING Rate Limit hit : 60 sec backoff triggered
    2023-09-28 20:42:18 INFO Loaded 200 devices
    2023-09-28 20:42:18 INFO Time elapsed loading device details from FMC: 102.2 secs
    2023-09-28 20:42:18 INFO Writing devices to CSV file (./output.csv)
    2023-09-28 20:42:18 INFO Time elapsed for writing CSV file: 0.0 secs

Note in the above example the FMC API rate limit was hit. The rate limit is 120 API calls per minute. This FMC has 200 devices that we needed to loop through to get detailed information about each. Thus we were forced to wait 60 seconds before continuing. 

### CSV File

By default the output is written to a CSV file called `output.csv` created in the directory where the script is run. This can be overridden by using the `-o` command line option. 