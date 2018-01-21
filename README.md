# Default Password Destroyer
> Simple tools to find on internet devices using a default password


## Usage

    root@ubuntu: python3 src/DPD.py -h
        
    usage: Default Password Destroyer [-h] [-v] [-u USERNAME] [-p PASSWORD] initial final

    Default Password Destroyer search for all IPs with the default password in an IP range.

    positional arguments:
      initial  initial IP
      final    final IP             

    optional arguments:
      -h,          --help               show this help message and exit
      -v,          --verbose            enabling verbose mode
      -u USERNAME, --username USERNAME  username to be tested, default is pi
      -p PASSWORD, --password PASSWORD  password to be tested, default is raspberry

    Use this script for educational purposes only.

## License

Copyright (c) 2018 Renato Tavares. Code released under the [GNU General Public License v3.0](LICENSE).

## Legal Notice

    [!] Disclaimer: Usage of this software for attacking targets without prior mutual consent is illegal. It is 
    the end user's responsibility to obey all applicable local, state and federal laws. Developers assume no 
    liability and are not responsible for any misuse or damage caused by this program. This software was created
    for educational use only. 