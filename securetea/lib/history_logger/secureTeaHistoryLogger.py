# -*- coding: utf-8 -*-
u"""SecureTea HistoryLogger

Project:
    ╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐╔╦╗┌─┐┌─┐
    ╚═╗├┤ │  │ │├┬┘├┤  ║ ├┤ ├─┤
    ╚═╝└─┘└─┘└─┘┴└─└─┘ ╩ └─┘┴ ┴
    Author: Kushal Majmundar <majmundarkushal9@gmail.com> , Jun 14 2019
    Version: 2.1
    Module: SecureTea

"""

import sys
import signal
import os
from .utils import check_root
from .historylogger_logger import HistoryLogger

class SecureTeaHistoryLogger(object):
    """SecureTeaHistoryLogger class."""

    def __init__(self, debug=False):
        """
        Initialize SecureTeaHistoryLogger

        Args:
            debug (bool): Log on terminal or not

        Raises:
            None

        Returns:
            None
        """
        # Initialize logger
        self.debug = debug
        self.logger = HistoryLogger(
                __name__,
                debug=debug
        )
        if not check_root():
            self.logger.log(
                "Please run as root exiting.",
                logtype="error"
            )
            sys.exit(0)

    def init_logger(self, debug=False):
        """
        Initialize SecureTeaHistoryLogger Files

        Args:
            debug (bool): Log on terminal or not

        Raises:
            None

        Returns:
            None
        """
        bash_export = 'export PROMPT_COMMAND=\'RETRN_VAL=$?;logger -p local6.debug "$(whoami) $(hostname -I) : $(history 1 | sed "s/^[ ]*[0-9]\+[ ]*//" )"\''
        log_file = "local6.*    /var/log/securetea_history_logger.log"
        log_rotation = "/var/log/securetea_history_logger.log"

        f_create = open("/etc/bash.bashrc", "a+")
        f_create.close()

        f_create = open("/etc/bashrc", "a+")
        f_create.close()

        f_create = open("/etc/rsyslog.d/bash.conf", "a+")
        f_create.close()

        f_create = open("/etc/logrotate.d/syslog", "a+")
        f_create.close()

        f_create = open("/etc/logrotate.d/rsyslog", "a+")
        f_create.close()

        f_bash = open("/etc/bash.bashrc", "r")
        if bash_export in f_bash.read():
            f_bash.close()
        else:
            f_bash.close()
            with open("/etc/bash.bashrc", "a") as f_bash:
                f_bash.write('\n')
                f_bash.write(bash_export)
        f_bash = open("/etc/bashrc", "r")
        if bash_export in f_bash.read():
            f_bash.close()
        else:
            f_bash.close()
            with open("/etc/bashrc", "a") as f_bash:
                f_bash.write('\n')
                f_bash.write(bash_export)
        self.logger.printinfo("Bash setup correctly")

        f_log_file = open("/etc/rsyslog.d/bash.conf", "r")
        if log_file in f_log_file.read():
            f_log_file.close()
        else:
            f_log_file.close()
            with open("/etc/rsyslog.d/bash.conf", "a") as f_log_file:
                f_log_file.write('\n')
                f_log_file.write(log_file)
        self.logger.printinfo("Rsys logging rules added")

        f_rotation_file = open("/etc/logrotate.d/rsyslog", "r")
        if log_rotation in f_rotation_file.read():
            f_rotation_file.close()
        else:
            f_rotation_file.close()
            with open("/etc/logrotate.d/rsyslog", "a") as f_rotation_file:
                f_rotation_file.write('\n')
                f_rotation_file.write(log_rotation)
        f_rotation_file = open("/etc/logrotate.d/syslog", "r")
        if log_rotation in f_rotation_file.read():
            f_rotation_file.close()
        else:
            f_rotation_file.close()
            with open("/etc/logrotate.d/syslog", "a") as f_rotation_file:
                f_rotation_file.write('\n')
                f_rotation_file.write(log_rotation)
        self.logger.printinfo("Rsys log rotation added")

        os.system("sudo service rsyslog restart")
        self.logger.printinfo("rsyslog service restarted")
        self.logger.printinfo(f"Logs available at : {log_rotation}")

        os.system("exec bash")
        os.popen("source /etc/bash.bashrc")
        os.popen("source /etc/bashrc")
        os.popen("sudo service rsyslog restart")
        os.system("sudo service rsyslog restart")
        self.logger.printinfo("bash configurations loaded")

    def signal_handler(self, sig, frame):
        """
        Handle Ctrl + C

        Args:
            sig : Signal
            frame : Frame

        Raises:
            None

        Returns:
            None
        """
        self.logger.printinfo("SIGINT detected")

        bash_export = 'export PROMPT_COMMAND = \'RETRN_VAL = $?;logger -p local6.debug "$(whoami) [$$]: $(history 1 | sed "s/^[ ]*[0-9]\\+[ ]*//" ) [$RETRN_VAL]"\''
        log_file = "local6.*    /var/log/securetea_history_logger.log"
        log_rotation = "/var/log/securetea_history_logger.log"

        with open("/etc/bash.bashrc", "r") as f_bash:
            f_bash_content = f_bash.read()
        f_bash_content = f_bash_content.replace(bash_export, '')
        with open("/etc/bash.bashrc", "w") as f_bash:
            f_bash.write(f_bash_content)
        with open("/etc/bashrc", "r") as f_bash:
            f_bash_content = f_bash.read()
        f_bash_content = f_bash_content.replace(bash_export, '')
        with open("/etc/bashrc", "w") as f_bash:
            f_bash.write(f_bash_content)
        self.logger.printinfo("Bash config removed")

        with open("/etc/rsyslog.d/bash.conf", "r") as f_log_file:
            f_log_file_content = f_log_file.read()
        f_log_file_content = f_log_file_content.replace(log_file, '')
        with open("/etc/rsyslog.d/bash.conf", "w") as f_log_file:
            f_log_file.write(f_log_file_content)
        self.logger.printinfo("Log config removed")

        with open("/etc/logrotate.d/rsyslog", "r") as f_log_rotation:
            f_log_rotation_content = f_log_rotation.read()
        f_log_rotation_content = f_log_rotation_content.replace(log_rotation, '')
        with open("/etc/logrotate.d/rsyslog", "w") as f_log_rotation:
            f_log_rotation.write(f_log_rotation_content)
        with open("/etc/logrotate.d/syslog", "r") as f_log_rotation:
            f_log_rotation_content = f_log_rotation.read()
        f_log_rotation_content = f_log_rotation_content.replace(log_rotation, '')
        with open("/etc/logrotate.d/syslog", "w") as f_log_rotation:
            f_log_rotation.write(f_log_rotation_content)
        self.logger.printinfo("Log-rotation config removed")

        os.system("sudo service rsyslog restart")
        self.logger.printinfo("rsyslog service restarted")

        os.system("exec bash")
        os.popen("source /etc/bash.bashrc")
        os.popen("source /etc/bashrc")


    def start(self):
        """
        Start HistoryLogger

        Args:
            None

        Raises:
            None

        Returns:
            None
        """
        try:
            self.init_logger(self.debug)
            signal.signal(signal.SIGINT, self.signal_handler)
            signal.signal(signal.SIGTERM, self.signal_handler)
            signal.pause()
        except Exception as e:
            self.logger.log(f"Error occurred: {str(e)}", logtype="error")
