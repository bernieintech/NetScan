# Network Asset Discovery

A lightweight network discovery and asset-inventory tool for small business
environments. It enumerates every device on a network segment, identifies the
hardware vendor, maintains a baseline over time, and flags devices that have
never been seen before.

Built as the discovery layer of a larger goal: **detecting the gap between the
devices an organization *thinks* it manages and the devices actually present on
its network.**

## The problem

Most small businesses cannot answer a question their cyber-insurance
questionnaire asks directly: *"Do you maintain an asset inventory?"*

They have a firewall. They do not have visibility. Unmanaged laptops, personal
phones, forgotten IoT devices, a contractor's machine, an aging printer nobody
owns — these are where incidents begin, and nobody is watching for them.

## Why ARP

The tool discovers devices using **ARP (Address Resolution Protocol)** rather
than ping sweeps, and that choice is deliberate:

> Any device functioning on a network **must** answer ARP. It can be configured
> to ignore ICMP, drop port scans, and run a restrictive host firewall — and it
> will still answer ARP, because without doing so it could not communicate at
> all.

This finds hosts that a ping sweep silently misses.

## What it does

- **ARP sweep** across one or more configured network ranges
- **Vendor identification** from the MAC address OUI
- **Randomized-MAC detection** — checks the locally-administered bit to
  distinguish a privacy/rotating MAC (modern phones) from a manufacturer-
  assigned address
- **Persistent baseline** in CSV, keyed by MAC address, tracking first-seen and
  last-seen timestamps
- **New-device alerting** — anything absent from the baseline is flagged

## Sample output (sanitized)

```
Scanning 192.168.10.0/24 ...

IP ADDRESS       MAC ADDRESS          VENDOR               STATUS
----------------------------------------------------------------------------------
192.168.10.1     aa:bb:cc:00:11:22    NetgearInc           known
192.168.10.24    aa:bb:cc:33:44:55    IntelCor             known
192.168.10.39    7e:bb:cc:66:77:88    Unknown              *** NEW (randomized) ***
192.168.10.52    aa:bb:cc:99:aa:bb    HewlettP             known

[!] 1 new device(s) since the last scan:
    192.168.10.39  7e:bb:cc:66:77:88  Unknown   (randomized MAC - probably a phone, not an intruder)

Baseline file: known_devices.csv
4 device(s) known in total.
```

## Design principles

- **Baseline keyed by MAC, not IP.** DHCP reassigns addresses constantly; the
  MAC does not. Keying on IP would report a "new device" every time a laptop
  reconnects.
- **Randomized MACs are labelled, not alarmed on.** A rotating phone address
  appears new on every rotation. Flagging it as an intruder produces alert
  fatigue — and alert fatigue is how genuine intrusions get ignored.
- **Deterministic interface selection.** The network interface is pinned in
  configuration rather than auto-selected, so behaviour does not vary between
  runs on multi-homed machines.
- **Fail loud, not silent.** Missing configuration raises a clear instruction
  rather than an opaque stack trace.
- **Resilient lookups.** A failed vendor lookup degrades to "Unknown" instead
  of terminating the scan. One bad record never kills a run.
- **No environment in the repository.** Interface names, network ranges and
  scan results stay in git-ignored local files.

## Requirements

- Python 3.x
- [Scapy](https://scapy.net/) — `pip install scapy`
- **Npcap** (Windows) — raw packet capture driver, https://npcap.com
  (Linux/macOS use libpcap, typically already present)
- **Administrator / root privileges** — raw packet access is privileged by design

## Setup

1. Copy `config.example.py` to `config.py`

2. Fill in your interface name, target network range(s), and timeout. Find your
   interface with:

   ```
   python -c "from scapy.all import conf; print(conf.ifaces)"
   ```

3. Run with elevated privileges:

   ```
   python arp_scan.py
   ```

`config.py` and `known_devices.csv` are git-ignored. A device inventory is a map
of a network and should be treated as sensitive.

## Known limitations

Stated plainly, because a security tool that overstates itself is worse than no
tool:

- **ARP operates at Layer 2 and cannot cross subnets or VLANs.** Segmented
  networks require a scan per segment, a Layer 3 method where inter-segment
  routing is permitted, or data pulled from the router.
- **MAC addresses can be spoofed**, and modern mobile devices randomize them.
  This provides *visibility*, not identity.
- **A scan is a snapshot, not a census.** Devices that are powered off, asleep,
  or in a Wi-Fi power-saving state may not respond. The persistent baseline
  exists to compensate for this over time.
- **Client/AP isolation** on guest and IoT networks can block device-to-device
  traffic even within a single subnet.
- **The tool does not yet report known-but-absent devices.** A device that
  disappears can matter as much as one that appears.
- **Authorized networks only.** Packet-level discovery should only ever be run
  against networks you have explicit permission to scan.

- **ARP replies are trusted as received.** A malicious device can answer ARP for
  addresses it does not own, flooding the inventory with phantom entries.
  Detecting one MAC that claims many IPs is both the mitigation and a planned
  feature.
- **The baseline file is trusted but not integrity-checked.** Anyone able to
  edit it could register a device as known and permanently suppress its alert.

## Roadmap

1. Approved-device registry with friendly names
2. Reporting on known-but-absent devices
3. Scheduled runs with weekly inventory reports
4. Router DHCP-lease ingestion — the only discovery method that crosses
   isolated network segments
5. **Shadow Device Gap Report** — cross-reference devices registered in
   Microsoft Entra ID against devices actually responding on the network. The
   difference is the organization's blind spot, and it is the reason this tool
   exists.
3. ARP-spoofing detection and baseline integrity verification

## Skills applied

Python (functions, error handling, file I/O, CSV, dictionaries, list
comprehensions, bitwise operations) · Scapy packet crafting · ARP and Layer
2/Layer 3 networking · MAC/OUI and locally-administered bit analysis · network
segmentation and VLAN boundaries · configuration separation and secrets hygiene
· Git/GitHub workflow.

## Notes

This tool grew out of coursework in Scripting & Automation (CIT 112) — Python
functions and error handling, file and CSV handling, dictionaries, regular
expressions and the Scapy packet-crafting module — rebuilt as something that
solves a real problem rather than satisfies an assignment. The networking
decisions draw on CompTIA Security+, Network+ and Cisco CCNA study, and were
tested against a deliberately segmented home lab of three isolated SSIDs, which
forced multi-segment behaviour to be handled from the outset rather than
retrofitted.

Reference material, documentation and AI assistance were used for research and
code review, as any current practitioner uses them. Every design decision and
limitation documented above is one I can explain and defend.

## License

All rights reserved (portfolio demonstration).