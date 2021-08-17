#!/bin/bash
# SecureTea install Dependencies.
# Project:
#     ╔═╗┌─┐┌─┐┬ ┬┬─┐┌─┐╔╦╗┌─┐┌─┐
#     ╚═╗├┤ │  │ │├┬┘├┤  ║ ├┤ ├─┤
#     ╚═╝└─┘└─┘└─┘┴└─└─┘ ╩ └─┘┴ ┴
#     Version: 2.1
#     Module: SecureTea
# Attributes:
#     distros : APT package manager based
#     files_definition (TYPE): Dependencies installation script

apt-get update

apt-get install software-properties-common # installation of python3 and python3-pip
add-apt-repository ppa:deadsnakes/ppa
apt-get update
apt-get install python3
apt-get install python3-pip # python3 and pip installed

apt install -y python3-setuptools build-essential python3-dev libnfnetlink-dev libnetfilter-queue-dev libnetfilter-queue1 rsyslog
service rsyslog restart
apt-get install -y clamav # dependencies installed

apt-get install exiftool   # dependencies for steg analysis
apt-get install pngcheck
apt-get install foremost
apt-get install steghide
apt-get install stegosuite

apt-get install curl    # dependency for API interaction.

apt-get install git # installing git
python3 -m pip install git+https://github.com/kti/python-netfilterqueue

python3 -m pip install -r requirements.txt
python3 -m pip install -r requirements.txt # statement repeated on purpose
