#!/usr/bin/env python
# -*- coding: utf-8 -*-

"""
Default Password Destroyer
Copyright (C) 2018  Renato Tavares <dr.renatotavares@gmail.com>

This program is free software: you can redistribute it and/or modify
it under the terms of the GNU General Public License as published by
the Free Software Foundation, either version 3 of the License, or
(at your option) any later version.

This program is distributed in the hope that it will be useful,
but WITHOUT ANY WARRANTY; without even the implied warranty of
MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
GNU General Public License for more details.

You should have received a copy of the GNU General Public License
along with this program.  If not, see <http://www.gnu.org/licenses/>.
"""

import time
import queue
import socket
import sqlite3
import argparse
import ipaddress
import threading
from pathlib import Path
from pexpect import pxssh
from contextlib import closing


class DefaultPasswordDestroyer(object):

    def __init__(self, args):

        self.NUM_THREADS = 50
        """int: Maximum number of threads to run."""

        self.MAX_SIZE_QUEUE = 50
        """int: maximum queue size."""

        self._threads = []
        """list of threads"""

        self.lock = threading.Lock()
        """obj: a primitive way to synchronize threads"""

        self.q = queue.Queue(self.MAX_SIZE_QUEUE)
        """obj: Constructor for a FIFO queue."""

        self.password = args.password
        """str: Password to be verified on each server"""

        self.username = args.username
        """str: Username to be verified on each server"""

        self._verbose = args.verbose
        """bool: check if verbose mode is enable"""

        self.verbose('args list is: {0}'.format(args))

        for _ in range(self.NUM_THREADS):
            t = threading.Thread(target=self.worker)
            t.daemon = True
            t.start()
            self._threads.append(t)

            self.verbose('Add the thread {0} in the pool.'.format(t.name))

        ips = self.gen_ip_list(args.initial, args.final)

        for ip in ips:
            self.verbose('Add IP {0} in queue.'.format(ip))
            self.q.put(str(ip))

        self.verbose('start join... will block until all tasks are done')
        self.q.join()

    def worker(self):
        """Function to perform the tests on a separate thread.

        Function responsible for performing all the tests on a particular 
        IP in order to check if it has the default password.
        
        Returns:
            None
        """
        while True:
            ip = self.q.get()

            if self.check_open_port(ip):
                if self.test_login(ip, self.username, self.password):
                    with self.lock:
                        self.save_to_database(ip, self.username, self.password)

            self.q.task_done()

    def save_to_database(self, ip, user, password):
        """Function to save the vulnerable IP in the database.

        Saves all vulnerable IPs in the SQLite database. SQLite does not work well with 
        threads, check if this code behaves well.

        Args:
            ip       (str): Vulnerable IP
            user     (str): SSH username
            password (str): SSH password
        
        Returns:
            bool: True if saved in database correctly, False otherwise.
        """
        path = str(Path('db/db.sqlite3').resolve())
        db = sqlite3.connect(path, check_same_thread=False)
        cursor = db.cursor()
        cursor.execute('''INSERT INTO vulnerable_ips (pass, user, ip) VALUES (?,?,?)''', (password, user, ip))
        db.commit()
        db.close()

    def gen_ip_list(self, initial_ip, final_ip):
        """Function to generate a list of IPs.

        Generates an IP list within the requested range. Uses yield to generate on demand 
        each IP, allowing each thread to request an IP without competing with each other.

        Args:
            initial_ip  (str): Initial IP
            final_ip    (str): Final IP

        Yields:
            str: The next generated IP inside the range.

        Examples:
            Examples should be written in doctest format, and should illustrate how
            to use the function.

            >>> print([i for i in example_generator(4)])
            [0, 1, 2, 3]
        """
        initial_ip, final_ip = ipaddress.ip_address(initial_ip), ipaddress.ip_address(final_ip)

        while initial_ip <= final_ip:
            yield initial_ip
            initial_ip += 1

    def write_to_file(self, data, file_name='output/status.log'):
        """Function to write data to a file.

        Just write the received data in a particular file on disk. Pre-formatting text 
        is the responsibility of the client.

        Args:
            data      (str): Data to be written.
            file_name (str): The file name.

        Returns:
            None
        """
        with open(str(Path(file_name).resolve()), "w+") as f:
            f.write(data)
            f.close()

    def check_open_port(self, ip='127.0.0.1', port=22):
        """Function that checks if a door is open.

        Uses the socket module to check if a particular port is open. In this 
        release only IPv4 (AF_INET) can be verified through the TCP protocol (SOCK_STREAM)

        Args:
            ip   (str): IP to be checked.
            port (int): Port to be checked.

        Returns:
            bool: True for open port, False otherwise.
        """
        with closing(socket.socket(socket.AF_INET, socket.SOCK_STREAM)) as sock:

            sock.settimeout(3)

            if sock.connect_ex((ip, port)) == 0:
                return True
            else:
                return False

    def test_login(self, ip='localhost', user='pi', password='raspberry'):
        """Function to test if SSH login works.

        Uses the user and password passed to try to login via SSH. If the 
        login is successful then we will know the user and the password.

        Args:
            ip       (str): IP to be checked.
            user     (int): User to be tested on SSH.
            password (int): Password to be tested on SSH.

        Returns:
            bool: True for a successful login, False otherwise.
        """
        try:
            s = pxssh.pxssh()
            s.login(ip, user, password)
            # s.sendline('uptime')  # We can also execute multiple command s.sendline('uptime;df -h')
            # s.prompt()  # match the prompt
            # print(s.before)  # print everything before the prompt.
            s.logout()
            return True
        except:
            return False

    def verbose(self, *args):
        """Print function for verbose mode

        Args:
            args (str): string(s) to be printed

        Returns:
            None
        """
        if self._verbose:
            print(*args)


if __name__ == '__main__':
    parser = argparse.ArgumentParser(prog='Default Password Destroyer',
                                     description="%(prog)s search for all IPs with the default password in an IP range.",
                                     epilog="Use this script for educational purposes only.")

    parser.add_argument('-v', '--verbose', help='enabling verbose mode', action='store_true', default=False)
    parser.add_argument('-u', '--username', help='username to be tested, default is pi', default='pi')
    parser.add_argument('-p', '--password', help='password to be tested, default is raspberry', default='raspberry')

    parser.add_argument("initial", help="Initial IP")
    parser.add_argument("final", help="Final IP")

    args = parser.parse_args()

    start_time = time.time()

    DefaultPasswordDestroyer(args)  # start...

    print("time elapsed: {:.2f}s".format(time.time() - start_time))
