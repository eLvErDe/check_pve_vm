#!/usr/bin/python3


# pylint: disable=line-too-long,bad-continuation


"""
Check etcd cluster v3 using etcdctl command
"""


import re
import os
import sys
import json
import tempfile
import argparse
import datetime
import dataclasses
from typing import Optional, Dict, Tuple, Union

import requests
import dateutil.parser

requests.packages.urllib3.disable_warnings()  # pylint: disable=no-member


class NagiosException(Exception):
    """
    Raised to return a Nagios state
    """

    def __init__(self, message: str, multiline: Optional[str] = None) -> None:
        super().__init__(message)
        self.multiline = multiline


class NagiosUnknown(NagiosException):
    """
    Raised to return unknown Nagios state
    """


class NagiosCritical(NagiosException):
    """
    Raised to return critical Nagios state
    """


class NagiosWarning(NagiosException):
    """
    Raised to return warning Nagios state
    """


class NagiosOk(NagiosException):
    """
    Raised to return ok Nagios state
    """


@dataclasses.dataclass
class VmMetrics:
    """
    Represent VM metrics returned by Proxmox REST API

    See https://pve.proxmox.com/pve-docs/api-viewer/#/cluster/resources which is NOT up to date sadly

    :param node: Proxmox node name where the VM is running on, e.g: proxmox-site1
    :type node: str
    :param name: Name of the VM, e.g: server-site1.domain.com
    :type name: str
    :param type: Type of VM, e.g: qemu
    :type type: str
    :param template: Probably a boolean as int saying if the VM is a template or not (undocumented), e.g: 0
    :type template: int
    :param vmid: VM unique identifier in the cluster, e.g: 101
    :type vmid: int
    :param status: Status of the VM, e.g: running
    :type status: str
    :param uptime: Uptime of the VM in seconds, e.g: 922717
    :type uptime: int
    :param netin: Counter of network bytes going in, e.g: 394239811
    :type netin: int
    :param netout: Counter of network bytes going out, e.g: 1389908051
    :type netout: int
    :param diskread: Counter of disk bytes being read, e.g: 2892860626
    :type diskread: int
    :param diskwrite: Counter of disk bytes being written, e.g: 3449019392
    :type diskwrite: int
    :param maxmem: Maximum RAM available in bytes, e.g: 4294967296
    :type maxmem: int
    :param mem: Currently used RAM in bytes, e.g: 1920292654
    :type mem: int
    :param maxcpu: Maximum number of CPUs available, e.g: 4
    :type maxcpu: int
    :param cpu: Currently used CPUs, e.g: 0.00247814375363615
    :type cpu: float
    :param maxdisk: Maximum disk size in bytes, e.g: 1395864371200
    :type maxdisk: int
    :param disk: Currently used disk size (seems to not be working here with Linux guest), e.g: 0
    :type disk: int
    :param timestamp: Timestamp as an iso8601 string
    :type timestamp: str
    :raise AssertionError: If provided parameters failed to validate
    """

    node: str
    name: str
    type: str
    template: int
    id: str
    vmid: int
    status: str
    uptime: int
    netin: int
    netout: int
    diskread: int
    diskwrite: int
    maxmem: int
    mem: int
    maxcpu: int
    cpu: float
    maxdisk: int
    disk: int
    timestamp: str

    @property
    def timestamp_dt(self) -> datetime.datetime:
        """
        Return self.timestamp as datetime.datetime instance

        :getter: Return self.timestamp as datetime.datetime instance
        """

        return dateutil.parser.parse(self.timestamp)

    def __post_init__(self) -> None:
        assert isinstance(self.node, str) and self.node, "node parameter must be a non-empty string"
        assert isinstance(self.name, str) and self.name, "name parameter must be a non-empty string"
        assert isinstance(self.type, str) and self.type, "type parameter must be a non-empty string"
        assert isinstance(self.template, int), "template parameter must be an integer"
        assert isinstance(self.id, str) and self.id, "id parameter must be a non-empty string"
        assert isinstance(self.vmid, int) and self.vmid > 0, "vmid parameter must be a positive integer"
        assert isinstance(self.status, str) and self.status, "status parameter must be a non-empty string"
        assert isinstance(self.uptime, int) and self.uptime >= 0, "uptime parameter must be a positive or zero integer"
        assert isinstance(self.netin, int) and self.netin >= 0, "netin parameter must be a positive or zero integer"
        assert isinstance(self.netout, int) and self.netout >= 0, "netout parameter must be a positive or zero integer"
        assert isinstance(self.diskread, int) and self.diskread >= 0, "diskread parameter must be a positive or zero integer"
        assert isinstance(self.diskwrite, int) and self.diskwrite >= 0, "diskwrite parameter must be a positive or zero integer"
        assert isinstance(self.maxmem, int) and self.maxmem > 0, "maxmem parameter must be a positive integer"
        assert isinstance(self.mem, int) and self.mem >= 0, "mem parameter must be a positive or zero integer"
        assert isinstance(self.maxcpu, int) and self.maxcpu > 0, "maxcpu parameter must be a positive integer"
        assert isinstance(self.cpu, (float, int)) and self.cpu >= 0, "cpu parameter must be a positive or zero integer or float"
        assert isinstance(self.maxdisk, int) and self.maxdisk > 0, "maxdisk parameter must be a positive integer"
        assert isinstance(self.disk, int) and self.disk >= 0, "disk parameter must be a positive or zero integer"
        self.cpu = float(self.cpu)

    @classmethod
    def from_api_payload(cls, payload: Dict) -> "VmMetrics":
        """
        Build an instance of this class from Proxmox REST API payload

        :param payload: Single entry of API payload representing state of a VM
        :type payload: dict
        :raise AssertionError: If provided payload is incorrect
        :return: Instance of VmMetrics dataclass
        :rtype: VmMetrics
        """

        assert isinstance(payload, dict), "payload parameter must be a dict, got %s" % payload.__class__.__name__
        required_keys = [
            "node",
            "name",
            "type",
            "template",
            "id",
            "vmid",
            "status",
            "uptime",
            "netin",
            "netout",
            "diskread",
            "diskwrite",
            "maxmem",
            "mem",
            "maxcpu",
            "cpu",
            "maxdisk",
            "disk",
        ]
        for required_key in required_keys:
            assert required_key in payload, "payload parameter must have a %s key" % required_key

        return cls(
            node=payload["node"],
            name=payload["name"],
            type=payload["type"],
            template=payload["template"],
            id=payload["id"],
            vmid=payload["vmid"],
            status=payload["status"],
            uptime=payload["uptime"],
            netin=payload["netin"],
            netout=payload["netout"],
            diskread=payload["diskread"],
            diskwrite=payload["diskwrite"],
            maxmem=payload["maxmem"],
            mem=payload["mem"],
            maxcpu=payload["maxcpu"],
            cpu=payload["cpu"],
            maxdisk=payload["maxdisk"],
            disk=payload["disk"],
            timestamp=payload.get("timestamp", datetime.datetime.now(tz=datetime.timezone.utc).isoformat()),
        )


class NagiosArgumentParser(argparse.ArgumentParser):
    """
    Inherit from ArgumentParser but exit with Nagios code 3 (Unknown) in case of argument error
    """

    def error(self, message: str):
        print("UNKNOWN: Bad arguments (see --help): %s" % message)
        sys.exit(3)


class CheckProxmox:
    """
    Check etcd cluster v3 using etcdctl command
    """

    def __init__(self, base_url: str, username: str, password: str) -> None:
        assert isinstance(base_url, str) and base_url.startswith(
            ("http://", "https://")
        ), "base_url parameter must be a string starting with http:// or https://"
        assert isinstance(username, str) and username, "username parameter must be a non-empty string"
        assert isinstance(password, str) and password, "password parameter must be a non-empty string"
        self.base_url = base_url
        self.username = username
        self.password = password
        self.temp_dir = tempfile.gettempdir()
        self.script_name = re.sub(r"\.py$", "", os.path.basename(__file__))

    def get_ticket(self) -> str:
        """
        Get authentication token from Proxmox API

        :return: Authentication ticket to use in further calls
        :rtype: str
        """

        url = self.base_url + "/api2/json/access/ticket"
        payload = {"username": self.username, "password": self.password}

        resp = requests.post(url, json=payload, timeout=5, verify=False)
        resp.raise_for_status()

        result = resp.json()
        assert isinstance(result, dict), "expects dict when requesting auth ticket, got %s" % result.__class__.__name__
        assert "data" in result, "expects data key in response dict when requesting auth ticket"
        assert "ticket" in result["data"], "expects data.ticket key in response dict when requesting auth ticket"
        return result["data"]["ticket"]

    def get_vm_status(self, name_or_id: str) -> VmMetrics:
        """
        Get cluster nodes and their states

        :param name_or_id: Virtual machine name or id
        :type name_or_id: str
        :return: Dataclass representing virtual machine status including network and disk I/O counters
        :rtype: VmMetrics
        """

        assert isinstance(name_or_id, str) and name_or_id, "name_or_id parameter must be a non-empty string"

        ticket = self.get_ticket()

        url = self.base_url + "/api2/json/cluster/resources"
        params = {"type": "vm"}
        cookies = {"PVEAuthCookie": ticket}

        resp = requests.get(url, params=params, cookies=cookies, timeout=30, verify=False)
        resp.raise_for_status()

        result = resp.json()
        assert isinstance(result, dict), "expects dict when requesting auth ticket, got %s" % result.__class__.__name__
        assert "data" in result, "expects data key in response dict when requesting auth ticket"
        vm_list = result["data"]

        matching_vms = [x for x in vm_list if name_or_id in [x["name"], x["vmid"]]]
        assert matching_vms, "Unable to find any VM with name or id %s" % name_or_id
        assert len(matching_vms) == 1, "Multiple VM (%d) with name or id %s found" % (len(matching_vms), name_or_id)
        vm = matching_vms[0]  # pylint: disable=invalid-name
        # Example
        # vm = {
        #     "node": "proxmox-site1",
        #     "name": "server-site1.domain.com",
        #     "type": "qemu",
        #     "template": 0,
        #     "id": "qemu/101",
        #     "vmid": 101,
        #     "status": "running",
        #     "uptime": 922717,
        #     "netin": 394239811,
        #     "netout": 1389908051,
        #     "diskread": 2892860626,
        #     "diskwrite": 3449019392,
        #     "maxmem": 4294967296,
        #     "mem": 1920292654,
        #     "maxcpu": 4,
        #     "cpu": 0.00247814375363615,
        #     "maxdisk": 1395864371200,
        #     "disk": 0
        # }

        parsed = VmMetrics.from_api_payload(vm)
        return parsed

    def get_current_previous_states(self, name_or_id: str, check_type: str) -> Tuple[VmMetrics, VmMetrics, float]:
        """
        Get current states of VM from API, load previous state from JSON cache file and return these information

        :param name_or_id: Virtual machine name or id
        :type name_or_id: str
        :param check_type: Type of check to perform (used to create JSON cache file specific to this check)
        :type check_type: str
        :raise NagiosUnknown: If previous state is not known, if previous JSON cache file is invalid or if server time went back in time
        :return: Three elements tuple with new VM state (dataclass), previous VM state (dataclass) and offset in seconds between two measures
        :rtype: tuple
        """

        assert isinstance(name_or_id, str) and name_or_id, "name_or_id parameter must be a non-empty string"
        assert isinstance(check_type, str) and check_type, "check_type parameter must be a non-empty string"

        status_file = os.path.join(self.temp_dir, "%s_%s_%s.json" % (self.script_name, check_type, name_or_id))

        current_vm_state = self.get_vm_status(name_or_id)

        if os.path.exists(status_file):
            try:
                with open(status_file, "r") as previous_vm_state_fh:
                    previous_vm_state = VmMetrics.from_api_payload(json.load(previous_vm_state_fh))
            except Exception as exc:  # pylint: disable=broad-except
                with open(status_file, "w") as previous_vm_state_fh:
                    json.dump(dataclasses.asdict(current_vm_state), previous_vm_state_fh)
                raise NagiosUnknown("Unable to load previous state from file at %s: %s: %s" % (status_file, exc.__class__.__name__, exc))
        else:
            with open(status_file, "w") as previous_vm_state_fh:
                json.dump(dataclasses.asdict(current_vm_state), previous_vm_state_fh)
            raise NagiosUnknown("First execution, creating buffer...")

        # Previous state has been loaded, write new state as previous
        with open(status_file, "w") as previous_vm_state_fh:
            json.dump(dataclasses.asdict(current_vm_state), previous_vm_state_fh)

        offset_seconds = (current_vm_state.timestamp_dt - previous_vm_state.timestamp_dt).total_seconds()
        if offset_seconds <= 0:
            raise NagiosUnknown(
                "Got previous state at %s and current state at %s, went back in time ?" % (previous_vm_state.timestamp, current_vm_state.timestamp)
            )

        return current_vm_state, previous_vm_state, offset_seconds

    @staticmethod
    def sizeof_fmt(num: Union[int, float], suffix: str = "B") -> str:
        """
        Pretty format unit for displaying bytes/s or bits/s

        :param num: Value to format
        :type num: int or float
        :param suffix: Base unit suffix, e.g: Bytes/s
        :type suffix: str
        :return: Formatted string with best unit (kilo, mega...)
        :rtype: str
        """

        for unit in ["", "K", "M"]:
            if abs(num) < 1024.0:
                return "%3.1f%s%s" % (num, unit, suffix)
            num /= 1024.0
        return "%.1f%s%s" % (num, "G", suffix)

    def evaluate_disk_io(  # pylint: disable=too-many-arguments,too-many-locals
        self, name_or_id: str, read_warning: Optional[int], read_critical: Optional[int], write_warning: Optional[int], write_critical: Optional[int]
    ) -> None:
        """
        Get disk I/O for given VM, evaluate thresholds and read/store metrics as JSON so counters
        can be compared to previous values

        :param name_or_id: Virtual machine name or id
        :type name_or_id: str
        :param read_warning: Maximum disk read speed in KBytes/s before trigger warning status, None for no threshold
        :type read_warning: int, optional
        :param read_critical: Maximum disk read speed in KBytes/s before trigger critical status, None for no threshold
        :type read_critical: int, optional
        :param write_warning: Maximum disk write speed in KBytes/s before trigger warning status, None for no threshold
        :type write_warning: int, optional
        :param write_critical: Maximum disk write speed in KBytes/s before trigger critical status, None for no threshold
        :type write_critical: int, optional
        :raise NagiosUnknown: If previous state is not known, if previous JSON cache file is invalid or if server time went back in time,
            or if disk read/write counters offset is negative (counter looped) or current state could not be retrieved from Proxmox API
        :raise NagiosWarning: If counters have been analyzed and at least one counter is above warning thresholds (but none above critical thresholds)
        :raise NagiosCritical: If counters have been analyzed and at least one counter is above critical thresholds
        :raise NagiosOk: If counters have been analyzed and read/write below thresholds (or thresholds not set)
        """

        # name_or_id asserted by self.get_current_previous_states method
        assert read_warning is None or isinstance(read_warning, int) and read_warning >= 0, "read_warning parameter must be a positive or zero integer or None"
        assert (
            read_critical is None or isinstance(read_critical, int) and read_critical >= 0
        ), "read_critical parameter must be a positive or zero integer or None"
        assert (
            write_warning is None or isinstance(write_warning, int) and write_warning >= 0
        ), "write_warning parameter must be a positive or zero integer or None"
        assert (
            write_critical is None or isinstance(write_critical, int) and write_critical >= 0
        ), "write_critical parameter must be a positive or zero integer or None"

        current_vm_state, previous_vm_state, offset_seconds = self.get_current_previous_states(name_or_id, "disk_io")

        read_bytes = current_vm_state.diskread - previous_vm_state.diskread
        if read_bytes < 0:
            raise NagiosUnknown("Got negative number of bytes read, counter has probably looped")
        read_bytes_speed_b = read_bytes / offset_seconds
        read_bytes_speed_kb = int(round(read_bytes_speed_b / 1024))
        write_bytes = current_vm_state.diskwrite - previous_vm_state.diskwrite
        if write_bytes < 0:
            raise NagiosUnknown("Got negative number of bytes written, counter has probably looped")
        write_bytes_speed_b = write_bytes / offset_seconds
        write_bytes_speed_kb = int(round(write_bytes_speed_b / 1024))

        # Evaluate thresholds
        has_warning = False
        has_critical = False
        if read_warning is not None and read_bytes_speed_kb > read_warning:
            has_warning = True
        if read_critical is not None and read_bytes_speed_kb > read_critical:
            has_critical = True
        if write_warning is not None and write_bytes_speed_kb > write_warning:
            has_warning = True
        if write_critical is not None and write_bytes_speed_kb > write_critical:
            has_critical = True

        perfdata = "disk_read=%dKB/s;%s;%s;0; disk_write=%dKB/s;%s;%s;0;" % (
            read_bytes_speed_kb,
            "" if read_warning is None else read_warning,
            "" if read_critical is None else read_critical,
            write_bytes_speed_kb,
            "" if write_warning is None else write_warning,
            "" if write_critical is None else write_critical,
        )
        if has_critical:
            raise NagiosCritical(
                "VM %s (%s): disk_read: %s, disk_write: %s|%s"
                % (
                    current_vm_state.name,
                    current_vm_state.status,
                    self.sizeof_fmt(read_bytes_speed_b, suffix="Bytes/s"),
                    self.sizeof_fmt(write_bytes_speed_b, suffix="Bytes/s"),
                    perfdata,
                )
            )
        if has_warning:
            raise NagiosWarning(
                "VM %s (%s): disk_read: %s, disk_write: %s|%s"
                % (
                    current_vm_state.name,
                    current_vm_state.status,
                    self.sizeof_fmt(read_bytes_speed_b, suffix="Bytes/s"),
                    self.sizeof_fmt(write_bytes_speed_b, suffix="Bytes/s"),
                    perfdata,
                )
            )
        raise NagiosOk(
            "VM %s (%s): disk_read: %s, disk_write: %s|%s"
            % (
                current_vm_state.name,
                current_vm_state.status,
                self.sizeof_fmt(read_bytes_speed_b, suffix="Bytes/s"),
                self.sizeof_fmt(write_bytes_speed_b, suffix="Bytes/s"),
                perfdata,
            )
        )

    def evaluate_net_io(  # pylint: disable=too-many-arguments,too-many-locals
        self, name_or_id: str, in_warning: Optional[int], in_critical: Optional[int], out_warning: Optional[int], out_critical: Optional[int]
    ) -> None:
        """
        Get network I/O for given VM, evaluate thresholds and read/store metrics as JSON so counters
        can be compared to previous values

        :param name_or_id: Virtual machine name or id
        :type name_or_id: str
        :param in_warning: Maximum network input bandwith in Kbits/s before trigger warning status, None for no threshold
        :type in_warning: int, optional
        :param in_critical: Maximum network input bandwith in Kbits/s before trigger critical status, None for no threshold
        :type in_critical: int, optional
        :param out_warning: Maximum network output bandwith in Kbits/s before trigger warning status, None for no threshold
        :type out_warning: int, optional
        :param out_critical: Maximum network output bandwith in Kbits/s before trigger critical status, None for no threshold
        :type out_critical: int, optional
        :raise NagiosUnknown: If previous state is not known, if previous JSON cache file is invalid or if server time went back in time,
            or if disk read/write counters offset is negative (counter looped) or current state could not be retrieved from Proxmox API
        :raise NagiosWarning: If counters have been analyzed and at least one counter is above warning thresholds (but none above critical thresholds)
        :raise NagiosCritical: If counters have been analyzed and at least one counter is above critical thresholds
        :raise NagiosOk: If counters have been analyzed and read/write below thresholds (or thresholds not set)
        """

        # name_or_id asserted by self.get_current_previous_states method
        assert in_warning is None or isinstance(in_warning, int) and in_warning >= 0, "in_warning parameter must be a positive or zero integer or None"
        assert in_critical is None or isinstance(in_critical, int) and in_critical >= 0, "in_critical parameter must be a positive or zero integer or None"
        assert out_warning is None or isinstance(out_warning, int) and out_warning >= 0, "out_warning parameter must be a positive or zero integer or None"
        assert out_critical is None or isinstance(out_critical, int) and out_critical >= 0, "out_critical parameter must be a positive or zero integer or None"

        current_vm_state, previous_vm_state, offset_seconds = self.get_current_previous_states(name_or_id, "net_io")

        in_bits = (current_vm_state.netin - previous_vm_state.netin) * 8
        if in_bits < 0:
            raise NagiosUnknown("Got negative number of bytes in, counter has probably looped")
        in_bits_speed_b = in_bits / offset_seconds
        in_bits_speed_kb = int(round(in_bits_speed_b / 1024))
        out_bits = (current_vm_state.netout - previous_vm_state.netout) * 8
        if out_bits < 0:
            raise NagiosUnknown("Got negative number of bits written, counter has probably looped")
        out_bits_speed_b = out_bits / offset_seconds
        out_bits_speed_kb = int(round(out_bits_speed_b / 1024))

        # Evaluate thresholds
        has_warning = False
        has_critical = False
        if in_warning is not None and in_bits_speed_kb > in_warning:
            has_warning = True
        if in_critical is not None and in_bits_speed_kb > in_critical:
            has_critical = True
        if out_warning is not None and out_bits_speed_kb > out_warning:
            has_warning = True
        if out_critical is not None and out_bits_speed_kb > out_critical:
            has_critical = True

        perfdata = "net_in=%dKb/s;%s;%s;0; net_out=%dKb/s;%s;%s;0;" % (
            in_bits_speed_kb,
            "" if in_warning is None else in_warning,
            "" if in_critical is None else in_critical,
            out_bits_speed_kb,
            "" if out_warning is None else out_warning,
            "" if out_critical is None else out_critical,
        )
        if has_critical:
            raise NagiosCritical(
                "VM %s (%s): net_in: %s, net_out: %s|%s"
                % (
                    current_vm_state.name,
                    current_vm_state.status,
                    self.sizeof_fmt(in_bits_speed_b, suffix="bits/s"),
                    self.sizeof_fmt(out_bits_speed_b, suffix="bits/s"),
                    perfdata,
                )
            )
        if has_warning:
            raise NagiosWarning(
                "VM %s (%s): net_in: %s, net_out: %s|%s"
                % (
                    current_vm_state.name,
                    current_vm_state.status,
                    self.sizeof_fmt(in_bits_speed_b, suffix="bits/s"),
                    self.sizeof_fmt(out_bits_speed_b, suffix="bits/s"),
                    perfdata,
                )
            )
        raise NagiosOk(
            "VM %s (%s): net_in: %s, net_out: %s|%s"
            % (
                current_vm_state.name,
                current_vm_state.status,
                self.sizeof_fmt(in_bits_speed_b, suffix="bits/s"),
                self.sizeof_fmt(out_bits_speed_b, suffix="bits/s"),
                perfdata,
            )
        )

    def evaluate_uptime(self, name_or_id: str, min_seconds_warning: Optional[int], min_seconds_critical: Optional[int]) -> None:
        """
        Get uptime for given VM and evaluate thresholds

        :param name_or_id: Virtual machine name or id
        :type name_or_id: str
        :param min_seconds_warning: Minimum uptime in seconds to trigger warning
        :type min_seconds_warning: int, optional
        :param min_seconds_critical: Minimum uptime in seconds to trigger critical
        :type min_seconds_critical: int, optional
        :raise NagiosUnknown: If current state could not be retreived from Proxmox API
        :raise NagiosWarning: If uptime is below warning threshold but above critical one
        :raise NagiosCritical: If uptime is below critical threshold
        :raise NagiosOk: If uptime is above both warning and critical thresholds
        """

        assert isinstance(name_or_id, str) and name_or_id, "name_or_id parameter must be a non-empty string"

        current_vm_state = self.get_vm_status(name_or_id)
        if current_vm_state.status != "running":
            raise NagiosCritical("VM %s is not running (%s)" % (current_vm_state.name, current_vm_state.status))

        start_iso8601 = (datetime.datetime.now() - datetime.timedelta(seconds=current_vm_state.uptime)).replace(microsecond=0).isoformat()

        if min_seconds_critical is not None and current_vm_state.uptime < min_seconds_critical:
            raise NagiosCritical(
                "VM %s (%s) is up for %d seconds (started at %s)" % (current_vm_state.name, current_vm_state.status, current_vm_state.uptime, start_iso8601)
            )
        if min_seconds_warning is not None and current_vm_state.uptime < min_seconds_warning:
            raise NagiosWarning(
                "VM %s (%s) is up for %d seconds (started at %s)" % (current_vm_state.name, current_vm_state.status, current_vm_state.uptime, start_iso8601)
            )
        raise NagiosOk(
            "VM %s (%s) is up for %d seconds (started at %s)" % (current_vm_state.name, current_vm_state.status, current_vm_state.uptime, start_iso8601)
        )


def parse_args() -> argparse.Namespace:  # pylint: disable=too-many-branches,too-many-statements
    """
    Parse command line arguments

    :return: argparse.Namespace object with all command line arguments as attributes (dash replace by underscore)
    :type: argparse.Namespace
    """

    parser = NagiosArgumentParser(description=__doc__.strip())
    parser.add_argument("--base-url", type=str, required=True, help="Base URL to Proxmox API", metavar="https://127.0.0.1:8006")
    parser.add_argument("--username", type=str, required=True, help="Username to authenticate with Proxmox API", metavar="root@pam")
    parser.add_argument("--password", type=str, required=True, help="Password to authenticate with Proxmox API", metavar="s3cr3t")
    parser.add_argument("--vm", type=str, required=True, help="Virtual machine name of VMID", metavar="vm1.domain.com")
    subparsers = parser.add_subparsers(help="Type of check to perform", dest="action")

    diskio_parser = subparsers.add_parser("diskio", help="Check VM disk I/O")  # Cannot user required=True here fot CentOS 7 compat
    diskio_parser.add_argument(
        "--read-warning", type=int, nargs="?", required=False, help="Maximum read speed in KBytes/s to trigger warning, -1 as null value", metavar="10000"
    )
    diskio_parser.add_argument(
        "--read-critical", type=int, nargs="?", required=False, help="Maximum read speed in KBytes/s to trigger critical, -1 as null value", metavar="20000"
    )
    diskio_parser.add_argument(
        "--write-warning", type=int, nargs="?", required=False, help="Maximum write speed in KBytes/s to trigger warning, -1 as null value", metavar="5000"
    )
    diskio_parser.add_argument(
        "--write-critical", type=int, nargs="?", required=False, help="Maximum write speed in KBytes/s to trigger critical, -1 as null value", metavar="10000"
    )

    netio_parser = subparsers.add_parser("netio", help="Check VM network bandwith")  # Cannot user required=True here fot CentOS 7 compat
    netio_parser.add_argument(
        "--in-warning", type=int, nargs="?", required=False, help="Maximum in speed in Kbits/s to trigger warning, -1 as null value", metavar="10000"
    )
    netio_parser.add_argument(
        "--in-critical", type=int, nargs="?", required=False, help="Maximum in speed in Kbits/s to trigger critical, -1 as null value", metavar="20000"
    )
    netio_parser.add_argument(
        "--out-warning", type=int, nargs="?", required=False, help="Maximum out speed in Kbits/s to trigger warning, -1 as null value", metavar="5000"
    )
    netio_parser.add_argument(
        "--out-critical", type=int, nargs="?", required=False, help="Maximum out speed in Kbits/s to trigger critical, -1 as null value", metavar="10000"
    )

    uptime_parser = subparsers.add_parser("uptime", help="Check minimum uptime")  # Cannot user required=True here fot CentOS 7 compat
    uptime_parser.add_argument(
        "--min-seconds-warning", type=int, nargs="?", required=False, help="Minimum uptime in seconds to trigger warning, -1 as null value", metavar="3600"
    )
    uptime_parser.add_argument(
        "--min-seconds-critical", type=int, nargs="?", required=False, help="Minimum uptime in seconds to trigger critical, -1 as null value", metavar="600"
    )

    args = parser.parse_args()

    if args.action is None:
        parser.error("An action must be specified (diskio, netio or uptime)")

    if args.action == "diskio":
        if args.read_warning == -1:
            args.read_warning = None
        if args.read_critical == -1:
            args.read_critical = None
        if args.write_warning == -1:
            args.write_warning = None
        if args.write_critical == -1:
            args.write_critical = None
        if args.read_warning is not None and args.read_critical is not None and args.read_warning > args.read_critical:
            parser.error("Warning read threshold cannot be greater than critical one")
        if args.write_warning is not None and args.write_critical is not None and args.write_warning > args.write_critical:
            parser.error("Warning write threshold cannot be greater than critical one")

    if args.action == "netio":
        if args.in_warning == -1:
            args.in_warning = None
        if args.in_critical == -1:
            args.in_critical = None
        if args.out_warning == -1:
            args.out_warning = None
        if args.out_critical == -1:
            args.out_critical = None
        if args.in_warning is not None and args.in_critical is not None and args.in_warning > args.in_critical:
            parser.error("Warning in threshold cannot be greater than critical one")
        if args.out_warning is not None and args.out_critical is not None and args.out_warning > args.out_critical:
            parser.error("Warning out threshold cannot be greater than critical one")

    if args.action == "uptime":
        if args.min_seconds_warning == -1:
            args.min_seconds_warning = None
        if args.min_seconds_critical == -1:
            args.min_seconds_critical = None
        if args.min_seconds_warning is not None and args.min_seconds_critical is not None and args.min_seconds_warning < args.min_seconds_critical:
            parser.error("Warning uptime threshold cannot be lower than critical one")

    return args


if __name__ == "__main__":

    CONFIG = parse_args()

    try:
        PROXMOX = CheckProxmox(base_url=CONFIG.base_url, username=CONFIG.username, password=CONFIG.password)
        if CONFIG.action == "diskio":
            PROXMOX.evaluate_disk_io(
                name_or_id=CONFIG.vm,
                read_warning=CONFIG.read_warning,
                read_critical=CONFIG.read_critical,
                write_warning=CONFIG.write_warning,
                write_critical=CONFIG.write_critical,
            )
        elif CONFIG.action == "netio":
            PROXMOX.evaluate_net_io(
                name_or_id=CONFIG.vm,
                in_warning=CONFIG.in_warning,
                in_critical=CONFIG.in_critical,
                out_warning=CONFIG.out_warning,
                out_critical=CONFIG.out_critical,
            )
        elif CONFIG.action == "uptime":
            PROXMOX.evaluate_uptime(name_or_id=CONFIG.vm, min_seconds_warning=CONFIG.min_seconds_warning, min_seconds_critical=CONFIG.min_seconds_critical)
        else:
            raise ValueError("Unsupported action %s" % CONFIG.action)
    except NagiosOk as exc:
        print("OK: %s" % exc)
        if exc.multiline:
            print(exc.multiline)
        sys.exit(0)
    except NagiosWarning as exc:
        print("WARNING: %s" % exc)
        if exc.multiline:
            print(exc.multiline)
        sys.exit(1)
    except NagiosCritical as exc:
        print("CRITICAL: %s" % exc)
        if exc.multiline:
            print(exc.multiline)
        sys.exit(2)
    except NagiosUnknown as exc:
        print("UNKNOWN: %s" % exc)
        if exc.multiline:
            print(exc.multiline)
        sys.exit(3)
    except Exception as exc:  # pylint: disable=broad-except
        print("UNKNOWN: %s: %s" % (exc.__class__.__name__, exc))
        sys.exit(3)
