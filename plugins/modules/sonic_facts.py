#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Gather Sonic Facts"""
# Copyright: Contributors to the Ansible project
# GNU General Public License v3.0+ (see COPYING or https://www.gnu.org/licenses/gpl-3.0.txt)
import json
import re
import shlex
import subprocess
import sys
from ipaddress import ip_address, ip_network


def normalizedip(ipInput):
    """
    Normalize IPv6 address. It can have leading 0 or not and both are valid.
    This function will ensure same format is used.
    """
    tmp = ipInput.split("/")
    try:
        ipaddr = ip_address(tmp[0]).compressed
    except ValueError:
        ipaddr = tmp[0]
    if len(tmp) == 2:
        return f"{ipaddr}/{tmp[1]}"
    if len(tmp) == 1:
        return ipaddr
    # We return what we get here, because it had multiple / (which is not really valid)
    return ipInput


def getsubnet(ipInput, strict=False):
    """Get subnet if IP address"""
    return ip_network(ipInput, strict=strict).compressed


def ipVersion(ipInput, strict=False):
    """Check if IP is valid.
    Input: str
    Returns: (one of) IPv4, IPv6, Invalid"""
    version = -1
    try:
        version = ip_network(ipInput, strict=strict).version
    except ValueError:
        pass
    if version != -1:
        return version
    tmpIP = ipInput.split("/")
    try:
        version = ip_address(tmpIP[0]).version
    except ValueError:
        pass
    return version


def make_json_obj(inptext):
    """Make JSON object from string"""
    try:
        return json.loads(inptext)
    except json.decoder.JSONDecodeError:
        return inptext


def run_commands(module, commands, check_rc):
    """Run commands and return output)"""
    output = []
    for command in commands:
        command = shlex.split(str(command))
        proc = subprocess.Popen(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        out, err = proc.communicate()
        if check_rc and proc.returncode != 0:
            raise Exception(f"Exception executing command {command}. Err: {err}")
        output.append(make_json_obj(out.decode("utf-8")))
    return output


class FactsBase:
    """Base class for Facts"""

    COMMANDS = []

    def __init__(self, module):
        self.module = module
        self.facts = {}
        self.responses = None

    def populate(self):
        """Populate responses"""
        self.responses = run_commands(self.module, self.COMMANDS, check_rc=False)

    def run(self, cmd):
        """Run commands"""
        return run_commands(self.module, cmd, check_rc=False)


class Config(FactsBase):
    """Default Class to get basic info"""

    COMMANDS = [
        "show runningconfiguration all",
    ]

    def populate(self):
        super(Config, self).populate()
        self.facts["config"] = self.responses[0]


class Interfaces(FactsBase):
    """All Interfaces Class"""

    COMMANDS = [
        "show interfaces status",
        "show runningconfiguration all",
        "show lldp neighbor",
    ]

    def populate(self):
        super(Interfaces, self).populate()
        self.facts["interfaces"] = {}
        for intfData in self.parseInterfacesOut():
            intfOut = self.facts["interfaces"].setdefault(intfData["Interface"], {})
            if "MTU" in intfData:
                intfOut["mtu"] = intfData["MTU"]
            if "Oper" in intfData:
                intfOut["operstatus"] = intfData["Oper"]
            if "Type" in intfData and intfData["Type"] != "N/A":
                intfOut["mediatype"] = intfData["Type"]
                intfOut["lineprotocol"] = "up"
            elif "Type" in intfData and intfData["Type"] == "N/A":
                intfOut["lineprotocol"] = "down"
            else:
                intfOut["lineprotocol"] = "unknown"
        self.facts.setdefault("info", {"macs": []})
        self.facts["info"]["macs"].append(self.getMac())
        self.parsePorts()
        self.parsePortChannel()
        self.parseVlans()
        self.parseVlanMembers()
        self.parseRoutes()
        self.parseLLDP()

    def parseInterfacesOut(self):
        """Parse Interfaces Out from show interfaces status"""
        keys = []
        padding = []
        keyLine = ""
        for lineNum, line in enumerate(self.responses[0].split("\n")):
            if lineNum == 0:
                keyLine = line
                continue
            if lineNum == 1:
                padding = [len(x) for x in line.split(" ") if x]
                keys = self.parseInterfaceLine(keyLine, padding)
                continue
            out = self.parseInterfaceLine(line, padding)
            if out:
                outD = dict(zip(keys, out))
                yield outD

    @staticmethod
    def parseInterfaceLine(line, padding):
        """Parse Interface Line"""
        if not line:
            return None
        outvals = []
        st = 0
        for item in padding:
            outvals.append(line[st : st + item + 2].strip())
            st += item + 2
        return outvals

    def getMac(self):
        """Get Mac from running config"""
        mac = None
        for _host, hostmetadata in self.responses[1]["DEVICE_METADATA"].items():
            mac = hostmetadata["mac"]
        return mac

    def parsePorts(self):
        """Parse Ports"""
        # Add All Ports
        mac = self.getMac()
        for portType in ["PORT", "PORTCHANNEL", "VLAN"]:
            for port, portDict in self.responses[1].get(portType, {}).items():
                out = self.facts["interfaces"].setdefault(port, {})
                if "speed" in portDict:
                    out["bandwidth"] = portDict["speed"]
                if mac:
                    out["macaddress"] = mac
                if "vrf_name" in portDict:
                    out["ip_vrf"] = portDict["vrf_name"]
                # https://github.com/sonic-net/sonic-buildimage/pull/13580
                # Older releases do not have mode key yet.
                # So for now we assume that every port is switchport;
                # TODO: Remove this once all releases have mode key.
                if portType != "VLAN":
                    if "mode" in portDict and portDict["mode"] == "trunk":
                        out["switchport"] = "yes"
                    elif "mode" not in portDict:
                        out["switchport"] = "yes"

    def parsePortChannel(self):
        """Parse Port Channel"""
        # Add All PorChannel members
        for port, _portDict in self.responses[1].get("PORTCHANNEL_MEMBER", {}).items():
            tmpPort = port.split("|")
            if len(tmpPort) != 2:
                print(f"Warning. PORTCHANNEL_MEMBER member key issue. Key: {port}")
                continue
            out = self.facts["interfaces"].setdefault(tmpPort[0], {})
            out.setdefault("channel-member", [])
            out["channel-member"].append(tmpPort[1])

    def parseVlans(self):
        """Parse Vlans"""
        # Add Vlan Interface info, like IPs.
        for port, _portDict in self.responses[1].get("VLAN_INTERFACE", {}).items():
            tmpPort = port.split("|")
            if len(tmpPort) != 2:
                print(f"Warning. VLAN_INTERFACE member key issue. Key: {port}")
                continue
            out = self.facts["interfaces"].setdefault(tmpPort[0], {})
            iptype = ipVersion(tmpPort[1])
            tmpIP = tmpPort[1].split("/")
            if iptype == 4:
                out.setdefault("ipv4", [])
                out["ipv4"].append({"address": tmpIP[0], "masklen": tmpIP[1]})
            elif iptype == 6:
                out.setdefault("ipv6", [])
                out["ipv6"].append(
                    {"address": normalizedip(tmpIP[0]), "masklen": (tmpIP[1])}
                )

    def parseVlanMembers(self):
        """Parse Vlan Members"""
        # Get all vlan members, tagged, untagged
        for port, portDict in self.responses[1].get("VLAN_MEMBER", {}).items():
            tmpPort = port.split("|")
            if len(tmpPort) != 2:
                print(f"Warning. VLAN_MEMBER member key issue. Key: {port}")
                continue
            out = self.facts["interfaces"].setdefault(tmpPort[0], {})
            tagMode = portDict.get("tagging_mode", "undefinedtagmode")
            if tagMode in ["tagged", "untagged"]:
                out.setdefault(tagMode, [])
                out[tagMode].append(tmpPort[1])

    def parseRoutes(self):
        """General Get Routes. INPUT: routeType = (int) 4,6"""
        for route, rDict in self.responses[1].get("STATIC_ROUTE", {}).items():
            tmpRoute = {
                "from": normalizedip(route),
                "to": rDict.get("nexthop", ""),
                "vrf": rDict.get("nexthop-vrf", ""),
                "intf": rDict.get("ifname", ""),
            }
            iptype = ipVersion(route)
            self.facts.setdefault(f"ipv{iptype}", [])
            self.facts[f"ipv{iptype}"].append({k: v for k, v in tmpRoute.items() if v})

    def parseLLDP(self):
        """Parse LLDP Information"""
        lldpOut = self.facts.setdefault("lldp", {})
        regexs = {
            "local_port_id": {"rules": [r"Interface:\s*([a-zA-Z0-9]*),.*"]},
            "remote_system_name": {"rules": [r"SysName:\s*(.+)"]},
            "remote_port_id": {
                "action": "ifnotmatched",
                "rules": [r"PortID:\s*ifname\s*(.+)", r"PortDescr:\s*(.+)"],
            },
            "remote_chassis_id": {
                "action": "overwrite",
                "rules": [r"ChassisID:\s*mac\s*(.+)", r"PortID:\s*mac\s*(.+)"],
            },
        }
        for entry in self.responses[2].split(
            "-------------------------------------------------------------------------------"
        ):
            entryOut = {}
            for regName, regex in regexs.items():
                match = re.search(regex["rules"][0], entry, re.M)
                if match:
                    entryOut[regName] = match.group(1)
                elif regex.get("action", "") == "ifnotmatched":
                    match = re.search(regex["rules"][1], entry, re.M)
                    if match:
                        entryOut[regName] = match.group(1)
                if regex.get("action", "") == "overwrite":
                    match = re.search(regex["rules"][1], entry, re.M)
                    if match:
                        entryOut[regName] = match.group(1)
            if "remote_port_id" not in entryOut:
                entryOut["remote_port_id"] = entryOut.get("remote_chassis_id", "")
            if "local_port_id" in entryOut:
                lldpOut.setdefault(entryOut["local_port_id"], entryOut)


FACT_SUBSETS = {"interfaces": Interfaces, "config": Config}


def main():
    """main entry point for module execution"""
    facts = {"gather_subset": list(FACT_SUBSETS.keys())}
    module = "Azure-SONiC"
    instances = []
    for key in facts["gather_subset"]:
        instances.append(FACT_SUBSETS[key](module))

    for inst in instances:
        if inst:
            inst.populate()
            facts.update(inst.facts)

    ansible_facts = {"ansible_facts": {}}
    for key, value in facts.items():
        key = f"ansible_net_{key}"
        ansible_facts["ansible_facts"][key] = value

    print(json.dumps(ansible_facts))
    sys.exit(0)


if __name__ == "__main__":
    main()
