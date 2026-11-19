"""
arp_scan.py - Local Network Device Discovery & Baseline Tracking
=================================================================
WHAT IT DOES
    Sends an ARP request to every address in a network range, records which
    devices answer, saves them to a baseline file, and flags anything NEW.

WHY ARP
    ARP (Address Resolution Protocol) is how a device asks "who has this IP?"
    Any device that is working on the network MUST answer ARP. It can ignore
    pings and block port scans, but it cannot ignore ARP and still communicate.
    That is why this finds devices a ping sweep would miss.

LIMITS
    - ARP is Layer 2: it CANNOT cross subnets/VLANs. Scan each network separately.
    - MACs can be spoofed, and modern phones rotate them (see is_randomized()).
    - Requires Administrator privileges and Npcap (raw packet access).
    - Only run on networks you are explicitly authorized to scan.

USAGE
    1. Copy config.example.py to config.py and fill in your own values.
    2. Open a terminal AS ADMINISTRATOR (raw packet access is privileged).
    3. python arp_scan.py
"""

# ---------------------------------------------------------------------------
# IMPORTS
# ---------------------------------------------------------------------------
from scapy.all import ARP, Ether, srp, conf   # craft packets, send, receive
from datetime import datetime                 # timestamps for first/last seen
import csv                                    # read/write the baseline file
import os                                     # build file paths safely


# ---------------------------------------------------------------------------
# CONFIGURATION
# ---------------------------------------------------------------------------
# Environment-specific settings live in config.py, which is git-ignored.
# Copy config.example.py to config.py and fill in your own values.
# This keeps machine- and network-specific details out of the repository.
try:
    from config import INTERFACE, TARGETS, SCAN_TIMEOUT
except ImportError:
    raise SystemExit(
        "\n[!] Missing config.py\n"
        "    Copy config.example.py to config.py and fill in your values.\n"
    )

# Pin the network card explicitly so Scapy never has to guess which one to use.
conf.iface = INTERFACE


# ---------------------------------------------------------------------------
# FILE PATHS
# ---------------------------------------------------------------------------
# Build the baseline path from the SCRIPT'S OWN location, not from whatever
# folder you happen to be sitting in when you run it. Same principle as
# $PSScriptRoot in the M365 tools: output always lands next to the script.
#   __file__          = this script's own path
#   os.path.abspath() = expand it to a full path
#   os.path.dirname() = strip the filename, leaving the folder
#   os.path.join()    = join folder + filename using the right slash for the OS
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
BASELINE_FILE = os.path.join(SCRIPT_DIR, "known_devices.csv")


# ---------------------------------------------------------------------------
# HELPER FUNCTIONS
# ---------------------------------------------------------------------------

def vendor_of(mac):
    """
    Look up the hardware manufacturer from a MAC address.

    The first half of a MAC is the OUI (Organizationally Unique Identifier),
    which is assigned to a manufacturer. Scapy ships a lookup table for it.

    Wrapped in try/except so a missing database or an odd MAC returns
    "Unknown" instead of killing the whole scan. One bad record should never
    stop the run - the same rule the M365 assessment tool follows.
    """
    try:
        return conf.manufdb._get_manuf(mac)
    except Exception:
        return "Unknown"


def is_randomized(mac):
    """
    Detect a randomized (privacy) MAC address.

    Every MAC's first byte carries a flag called the "locally administered" bit:
        bit CLEAR (0) = burned into the hardware by the manufacturer
        bit SET   (1) = invented by the device, i.e. a privacy/rotating MAC

    This matters a lot here. Modern phones rotate their MAC for privacy
    ("Private Wi-Fi Address" on iPhone/Android). Without this check, your own
    phone would be reported as a brand new device every time it rotates -
    and constant false alarms are how real intrusions get ignored.

    How the check works, step by step:
        mac.split(":")[0]  -> first pair of hex digits, e.g. "5e"
        int(..., 16)       -> convert that hex text to a number (0x5e = 94)
        & 0b00000010       -> keep only the second-lowest bit
        bool(...)          -> True if that bit was set
    """
    try:
        first_octet = int(mac.split(":")[0], 16)
        return bool(first_octet & 0b00000010)
    except Exception:
        return False
    

def sanitize(value):
    """
    Clean a value that arrived from a device we do not control.

    Two problems, one fix, because both have the same root cause:

      1. Excel executes any cell beginning with =, + , - or @ as a formula.
      2. Control characters (ANSI escape sequences) printed to a terminal can
         move the cursor, recolor output, or hide text entirely.

    Strip anything non-printable, then neutralize a leading formula character.
    """
    text = "".join(ch for ch in str(value) if ch.isprintable())
    if text and text[0] in ("=", "+", "-", "@"):
        return "'" + text
    return text

def scan(target):
    """
    ARP-sweep one network range. Returns a list of (ip, mac, vendor) tuples.

    Ether(dst="ff:ff:ff:ff:ff:ff") is the BROADCAST address - all Fs means
    "every device on this segment, listen up."

    The "/" operator stacks protocol layers: an Ethernet frame carrying an
    ARP request. That is the OSI model written as code.

    srp() = Send and Receive Packets at LAYER 2.
            (sr() without the "p" is the Layer 3 version, which CAN cross
            subnets - though not on this network, which is truly isolated.)

    srp() returns two lists: answered and unanswered. We only need the first,
    so the second is named "_", Python's convention for "I don't need this."
    """
    packet = Ether(dst="ff:ff:ff:ff:ff:ff") / ARP(pdst=target)
    answered, _ = srp(packet, timeout=SCAN_TIMEOUT, retry=2, verbose=False)

    # List comprehension: for every reply, build a tuple of three fields.
    #   r.psrc  = protocol source  = the responder's IP address
    #   r.hwsrc = hardware source  = the responder's MAC address
    return [(sanitize(r.psrc), sanitize(r.hwsrc), sanitize(vendor_of(r.hwsrc)))
            for sent, r in answered]


def load_baseline():
    """
    Read previously seen devices from the baseline CSV into a dictionary.

    The dictionary is keyed by MAC ADDRESS, not IP - deliberately.
    IP addresses change every time DHCP hands out a new lease (this router's
    pool runs .2 to .253). The MAC stays put. Track the thing that does not
    move, or the tool reports a "new device" every time a laptop reconnects.

    Returns an empty dictionary on the very first run, when no file exists yet.
    """
    known = {}
    if os.path.exists(BASELINE_FILE):
        # "with" is a context manager: it closes the file automatically,
        # even if something crashes partway through reading it.
        with open(BASELINE_FILE, newline="") as f:
            # DictReader hands back each row as a dictionary keyed by column
            # name, so we write row["mac"] instead of counting positions.
            for row in csv.DictReader(f):
                # A baseline written by an older version may be missing newer
                # columns. setdefault() fills a gap without overwriting
                # anything that is already there.
                row.setdefault("randomized", "")
                known[row["mac"]] = row
    return known


def save_baseline(known):
    """
    Write the updated device list back to the baseline CSV.

    newline="" is a Windows-specific fix: without it, Python's csv writer
    inserts a blank line between every row.
    """
    columns = ["mac", "ip", "vendor", "randomized", "first_seen", "last_seen"]
    with open(BASELINE_FILE, "w", newline="") as f:
        writer = csv.DictWriter(f, fieldnames=columns)
        writer.writeheader()
        for row in known.values():
            writer.writerow(row)


# ---------------------------------------------------------------------------
# MAIN PROGRAM
# ---------------------------------------------------------------------------

# One timestamp reused for this entire run, so every record agrees.
now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")

known = load_baseline()   # every device we have seen before
new_devices = []          # anything we have not

print(f"\nScanning {', '.join(TARGETS)} ...")
print(f"\n{'IP ADDRESS':<16} {'MAC ADDRESS':<20} {'VENDOR':<20} STATUS")
print("-" * 82)

for target in TARGETS:
    for ip, mac, vendor in scan(target):

        random_flag = "yes" if is_randomized(mac) else "no"

        if mac in known:
            # Seen before: refresh where it is and when we last saw it.
            known[mac]["ip"] = ip
            known[mac]["last_seen"] = now
            status = "known"
        else:
            # Never seen before: record it, and remember to report it.
            known[mac] = {
                "mac": mac,
                "ip": ip,
                "vendor": vendor,
                "randomized": random_flag,
                "first_seen": now,
                "last_seen": now,
            }
            new_devices.append((ip, mac, vendor, random_flag))
            # A rotating phone MAC is "new" on every rotation. Labelling it
            # keeps the plain "NEW" alert meaningful for genuine unknowns.
            if random_flag == "yes":
                status = "*** NEW (randomized) ***"
            else:
                status = "*** NEW ***"

        # vendor[:20] slices long manufacturer names so the columns stay tidy.
        print(f"{ip:<16} {mac:<20} {vendor[:20]:<20} {status}")

save_baseline(known)


# ---------------------------------------------------------------------------
# SUMMARY
# ---------------------------------------------------------------------------
if new_devices:
    print(f"\n[!] {len(new_devices)} new device(s) since the last scan:")
    for ip, mac, vendor, random_flag in new_devices:
        if random_flag == "yes":
            note = "   (randomized MAC - probably a phone, not an intruder)"
        else:
            note = ""
        print(f"    {ip}  {mac}  {vendor}{note}")
else:
    print("\nNo new devices since the last scan.")

print(f"\nBaseline file: {BASELINE_FILE}")
print(f"{len(known)} device(s) known in total.\n")