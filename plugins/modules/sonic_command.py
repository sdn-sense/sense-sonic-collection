#!/usr/bin/python3
# -*- coding: utf-8 -*-
"""
SENSE Azure Sonic Module, which is copied and called via Ansible from
SENSE Site-RM Resource Manager.

Main reasons for this script are the following:
    1. Azure Sonic does not have Ansible module
    2. Dell Sonic module depends on sonic-cli - and currently (140422) -
       it is broken due to python2 removal. See https://github.com/Azure/SONiC/issues/781
    3. It is very diff from normal switch cli, like:
          If vlan present on Sonic, adding it again will raise Exception (on Dell/Arista Switches, it is not)
          If vlan not cleaned (has member, ip, or any param) Sonic does not allow to remove vlan. First need to
          clean all members, params, ips and only then remove vlan.
    4. For BGP - We cant use SONiC config_db.json - as it is not rich enough, and does not support all features
       (route-map, ip list). Because of this - we have to rely on vtysh

With this script - as input, it get's information from Site-RM for which vlan and routing to configure/unconfigure
It checks with local configuration and applies the configs on Sonic with config command or routing with vtysh

Authors:
  Justas Balcas jbalcas (at) caltech.edu

Date: 2022/04/14
"""
import ast
import ipaddress
import json
import os
import re
import shlex
import subprocess
import sys

def normalizeIPAddress(ipInput):
    """Normalize IP Address"""
    tmpIP = ipInput.split("/")
    longIP = ipaddress.ip_address(tmpIP[0]).exploded
    if len(tmpIP) == 2:
        return f"{longIP}/{tmpIP[1]}"
    return longIP


def externalCommand(command):
    """Execute External Commands and return stdout and stderr."""
    command = shlex.split(command)
    with subprocess.Popen(
        command, stdout=subprocess.PIPE, stderr=subprocess.PIPE
    ) as proc:
        stdout, stderr = proc.communicate()
        exitCode = proc.wait()
        if exitCode != 0:
            raise Exception(
                f"{command} exited non-zero. Exit: {exitCode} Stdout: {stdout} Stderr: {stderr}"
            )
        return [stdout, stderr, exitCode]
    return ["", "", -1]


def sendviaStdIn(maincmd, commands):
    """Send commands to maincmd stdin"""
    if not isinstance(maincmd, list):
        maincmd = shlex.split(maincmd)
    with subprocess.Popen(
        maincmd, stdin=subprocess.PIPE, stdout=subprocess.PIPE
    ) as mainProc:
        singlecmd = ""
        for cmd in commands:
            singlecmd += f"{cmd}\n"
        mainProc.communicate(input=singlecmd.encode())


def strtojson(intxt):
    """str to json function"""
    out = {}
    try:
        out = ast.literal_eval(intxt)
    except ValueError:
        out = json.loads(intxt)
    except SyntaxError as ex:
        raise Exception(f"SyntaxError: Failed to literal eval dict. Err:{ex} ") from ex
    return out


def loadJson(infile):
    """Load json file and return dictionary"""
    out = {}
    fout = ""
    if not os.path.isfile(infile):
        raise Exception(f"File does not exist {infile}. Exiting")
    with open(infile, "r", encoding="utf-8") as fd:
        fout = fd.readlines()
    if fout:
        for line in fout:
            splline = line.split(": ", 1)
            if len(splline) == 2:
                out[splline[0]] = strtojson(splline[1])
    return out

class Main:
    """Main Sonic Class"""
    def __init__(self):
        self.args = None
        self.module_stdout = []
        self.module_stderr = []

    def execute(self):
        """Main execute"""
        senseconfig = loadJson(self.args["config"])
        print(senseconfig)

    def parseArgs(self, inFile):
        """Parse Args from input file"""
        if not os.path.isfile(inFile):
            raise Exception("Input File from param does not exist on Device.")
        params = {"debug": r"sonic_debug=(\S+)", "config": r"sonic_config=(\S+)"}
        args = {}
        with open(inFile, "r", encoding="utf-8") as fd:
            tmptxt = fd.read()
            for key, reg in params.items():
                match = re.search(reg, tmptxt, re.M)
                if match:
                    args[key] = match[1]
        return args


    def main(self):
        if len(sys.argv) != 2:
            raise Exception(f"Issue with passed arguments. Input: {sys.argv}")
        self.args = self.parseArgs(sys.argv[1])
        if not self.args.get("config", None):
            raise Exception(f"Issue with parsing input config. Input: {sys.argv}")
        self.execute()
        print(json.dumps({"changed": "ok"}))


if __name__ == "__main__":
    main = Main()
    main.main()
    sys.exit(0)
