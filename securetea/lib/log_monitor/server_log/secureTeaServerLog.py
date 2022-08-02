# -*- coding: utf-8 -*-
u"""SecureTea Server Log Monitor.

Project:
    ╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐╔╦╗┌─┐┌─┐
    ╚═╗├┤ │  │ │├┬┘├┤  ║ ├┤ ├─┤
    ╚═╝└─┘└─┘└─┘┴└─└─┘ ╩ └─┘┴ ┴
    Author: Abhishek Sharma <abhishek_official@hotmail.com> , Jun 12 2019
    Version: 1.3
    Module: SecureTea

"""
from securetea.lib.log_monitor.server_log.engine import Engine
from securetea.lib.log_monitor.server_log.server_logger import ServerLogger
from securetea.lib.log_monitor.server_log import utils
import sys


class SecureTeaServerLog(object):
    """SecureTeaServerLog Class."""

    def __init__(self,
                 debug=False,
                 log_type=None,
                 log_file=None,
                 window=30,
                 ip_list=None,
                 status_code=None):
        """
        Initialize ServerLog Monitor Engine.

        Args:
            debug (bool): Log on terminal or not
            type (str): Type of log file (Apache, Nginx)
            log_file (str): Path of the log file
            window (int): Days old log to process
            ip_list (str): List of IPs to filter
            status_code (str): List of status code to filter

        Raises:
            None

        Returns:
            None
        """
        # Initialize logger
        self.logger = ServerLogger(
                __name__,
                debug=debug
        )

        # Check running as root or not
        if not utils.check_root():
            self.logger.log(
                "Please start as root, exiting.",
                logtype="error"
            )
            sys.exit(0)

        if ip_list:
            ip_list = utils.get_list(ip_list)

        if status_code:
            status_code = utils.get_list(status_code)

        # Check the variables
        log_file = None if log_file == "" else log_file.strip(" ")
        log_type = None if log_type == "" else log_type.strip(" ")
        window = 30 if window == "" else int(window)
        # Create Engine
        self.engine_obj = Engine(
                        debug=debug,
                        log_type=log_type,
                        log_file=log_file,
                        window=window,
                        ip_list=ip_list,
                        status_code=status_code
                    )

    def run(self):
        """
        Run SecureTea Server Log Monitor.

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        try:
            # Start the engine
            self.engine_obj.run()
        except KeyboardInterrupt:
            self.logger.log(
                "Exiting.",
                logtype="info"
            )
