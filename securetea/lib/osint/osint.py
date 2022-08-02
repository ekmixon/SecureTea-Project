# -*- coding: utf-8 -*-
u"""OSINT module for SecureTea.

Project:
    ╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐╔╦╗┌─┐┌─┐
    ╚═╗├┤ │  │ │├┬┘├┤  ║ ├┤ ├─┤
    ╚═╝└─┘└─┘└─┘┴└─└─┘ ╩ └─┘┴ ┴
    Author: Abhishek Sharma <abhishek_official@hotmail.com> , Jul 15 2019
    Version: 1.4
    Module: SecureTea

"""

import socket
import ipwhois
import geocoder
import csv
import os

from securetea.lib.osint.osint_logger import OSINTLogger


class OSINT(object):
    """OSINT class."""

    def __init__(self, debug=False):
        """
        Initialize OSINT class.

        Args:
            debug (bool): Log on terminal or not

        Raises:
            None

        Returns:
            None
        """
        # Initialize logger
        self.logger = OSINTLogger(
            __name__,
            debug=debug
        )

        # Initialize CSV file fieldnames
        self.fieldnames = ['ip',
                           'host_name',
                           'arpa_domains',
                           'address',
                           'description',
                           'state',
                           'city',
                           'detailed_addr',
                           'postal_code']

        # Path to save generated CSV report
        self._REPORT_PATH = "/etc/securetea/report.csv"


    def reverse_dns_lookup(self, ip):
        """
        Peform reverse DNS lookup.

        Args:
            ip (str): IP address on which to perform operation

        Raises:
            None

        Returns:
            host_name (str): Name of the host
            arpa_domains (str): ARPA domain list
        """
        self.logger.log(
            f"Performing reverse DNS lookup on IP: {str(ip)}", logtype="info"
        )

        details = socket.gethostbyaddr(ip)
        host_name = details[0]
        arpa_domains = details[1]

        arpa_domains = ", ".join(arpa_domains) if arpa_domains != [] else "Not found"
        return host_name, arpa_domains

    def geo_lookup(self, ip_addr):
        """
        Find geographic location of the IP address.

        Args:
            ip_addr (str): IP address on which to perform operation

        Raises:
            None

        Returns:
            address (str): Found address of the IP
        """
        self.logger.log(
            f"Performing geographic lookup on IP: {str(ip_addr)}", logtype="info"
        )

        geocode_data = geocoder.ip(ip_addr)
        dict_data = geocode_data.json
        return dict_data["address"] or "Not found"

    def ip_whois(self, ip):
        """
        Peform WHOIS lookup of the IP.

        Args:
            ip (str): IP address on which to perform operation

        Raises:
            None

        Returns:
            ip_dict (dict): Dictionary of the details collected
        """
        self.logger.log(f"Performing IP WHOIS lookup on IP: {str(ip)}", logtype="info")
        ipwho = ipwhois.IPWhois(ip)
        ip_dict = ipwho.lookup_whois()

        description = ip_dict["asn_description"]
        state = ip_dict["nets"][0]["state"]
        city = ip_dict["nets"][0]["city"]
        detailed_addr = ip_dict["nets"][0]["address"]
        postal_code = ip_dict["nets"][0]["postal_code"]

        # Return the generated IP WHOIS dict
        return {
            "description": description or "Not found",
            "state": state or "Not found",
            "city": city or "Not found",
            "detailed_addr": detailed_addr or "Not found",
            "postal_code": postal_code or "Not found",
        }

    def collect_details(self, ip):
        """
        Collect details about the IP address.

        Args:
            ip (str): IP address on which to perform operation

        Raises:
            None

        Returns:
            ip_details_dict (dict): Dictionary containing the details about the IP
        """
        self.logger.log(f"Collecting details for IP: {str(ip)}", logtype="info")
        # Perform reverse DNS lookup
        host_name, arpa_domains = self.reverse_dns_lookup(ip=ip)
        # Peform geographic lookup
        address = self.geo_lookup(ip_addr=ip)
        # Perform IP WHOIS lookup
        ip_whois_dict = self.ip_whois(ip=ip)

        ip_details_dict = {
            "ip": ip,
            "host_name": host_name,
            "arpa_domains": arpa_domains,
            "address": address,
        }

        ip_details_dict |= ip_whois_dict

        return ip_details_dict

    def csv_writer(self, data):
        """
        Write dictionary details to CSV file.

        Args:
            data (dict): Data to write into CSV file

        Raises:
            None

        Returns:
            None
        """
        self.logger.log(
            "Writing details to CSV file",
            logtype="info"
        )
        if not os.path.isfile(self._REPORT_PATH):
            with open(self._REPORT_PATH, "w") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=self.fieldnames)
                # New file is being created, write the headers
                writer.writeheader()
                writer.writerow(data)
        else:
            with open(self._REPORT_PATH, "a") as csv_file:
                writer = csv.DictWriter(csv_file, fieldnames=self.fieldnames)
                writer.writerow(data)

    def perform_osint_scan(self, ip):
        """
        Perform OSINT scan on the given IP address.

        Args:
            ip (str): IP address on which to perform operation

        Raises:
            None

        Returns:
            None
        """
        self.logger.log(f"Performing OSINT scan on IP: {str(ip)}", logtype="info")
        # Collect details about the IP
        ip_details_dict = self.collect_details(ip=ip)
        # Write the details to the CSV file
        self.csv_writer(data=ip_details_dict)
