# Description

Simple Python script to be used as a Nagios check for Proxmox. It can check for disk and network bandwith with thresholds (none of existing monitoring scripts I found handle this).

# Examples

## Disk read/write:

```
python3 check_pve_vm.py --base-url https://10.1.2.3:8006 --username monitoring@pve --password p4ssw0rd --vm server-site1.domain.com diskio --write-warning 10000 --write-critical 20000
CRITICAL: VM server-site1.domain.com (running): disk_read: 631.9KBytes/s, disk_write: 90.9MBytes/s|disk_read=632KB/s;;;0; disk_write=93041KB/s;10000;20000;0;
```

## Network in/out:

```
python3 check_pve_vm.py --base-url https://10.1.2.3:8006 --username monitoring@pve --password p4ssw0rd --vm server-site1.domain.com netio --in-warning 10000 --in-critical 20000
OK: VM server-site1.domain.com (running): net_in: 3.3Kbits/s, net_out: 23.3Kbits/s|net_in=3Kb/s;10000;20000;0; net_out=23Kb/s;;;0;
```

## Uptime

```
python3 check_pve_vm.py --base-url https://10.1.2.3:8006 --username monitoring@pve --password p4ssw0rd --vm server-site1.domain.com uptime --min-seconds-warning 600
WARNING: VM server-site1.domain.com (running) is up for 476 seconds (started at 2021-05-17T11:45:35)
```
