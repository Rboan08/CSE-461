from mininet.topo import Topo
from mininet.node import CPULimitedHost
from mininet.node import Controller
from mininet.node import OVSBridge
from mininet.link import TCLink
from mininet.net import Mininet
from mininet.log import lg, info
from mininet.util import dumpNodeConnections
from mininet.cli import CLI

from subprocess import Popen, PIPE
from time import sleep, time
from multiprocessing import Process
from argparse import ArgumentParser

from monitor import monitor_qlen

import sys
import os
import math
import statistics

parser = ArgumentParser(description="Bufferbloat tests")
parser.add_argument('--bw-host', '-B',
                    type=float,
                    help="Bandwidth of host links (Mb/s)",
                    default=1000)

parser.add_argument('--bw-net', '-b',
                    type=float,
                    help="Bandwidth of bottleneck (network) link (Mb/s)",
                    required=True)

parser.add_argument('--delay',
                    type=float,
                    help="Link propagation delay (ms)",
                    required=True)

parser.add_argument('--dir', '-d',
                    help="Directory to store outputs",
                    required=True)

parser.add_argument('--time', '-t',
                    help="Duration (sec) to run the experiment",
                    type=int,
                    default=10)

parser.add_argument('--maxq',
                    type=int,
                    help="Max buffer size of network interface in packets",
                    default=100)

# Linux uses CUBIC-TCP by default that doesn't have the usual sawtooth
# behaviour.  For those who are curious, invoke this script with
# --cong cubic and see what happens...
# sysctl -a | grep cong should list some interesting parameters.
parser.add_argument('--cong',
                    help="Congestion control algorithm to use",
                    default="reno")

# Expt parameters
args = parser.parse_args()

class BBTopo(Topo):
    "Simple topology for bufferbloat experiment."

    def build(self, n=2):
        # create two hosts
        h1 = self.addHost('h1')
        h2 = self.addHost('h2')

        # Here I have created a switch.  If you change its name, its
        # interface names will change from s0-eth1 to newname-eth1.
        # This is the router
        switch = self.addSwitch('s0', cls=OVSBridge)

        # Add links with appropriate characteristics
        self.addLink(h1, switch, bw=(args.bw_host), delay='{}ms'.format(args.delay))
        self.addLink(h2, switch, bw=(args.bw_net), delay='{}ms'.format(args.delay), max_queue_size=(args.maxq))


# Simple wrappers around monitoring utilities.  You are welcome to
# contribute neatly written (using classes) monitoring scripts for
# Mininet!

def start_iperf(net):
    h1 = net.get('h1')
    h2 = net.get('h2')
    print("Starting iperf server...")
    # For those who are curious about the -w 16m parameter, it ensures
    # that the TCP flow is not receiver window limited.  If it is,
    # there is a chance that the router buffer may not get filled up.
    server = h2.popen("iperf -s -w 16m", shell=True)

    # Start the iperf client on h1.  Ensure that you create a
    # long lived TCP flow.
    client = h1.popen("iperf -c {} -t {}".format(h2.IP(), args.time), shell=True)

def start_qmon(iface, interval_sec=0.1, outfile="q.txt"):
    monitor = Process(target=monitor_qlen,
                      args=(iface, interval_sec, outfile))
    monitor.start()
    return monitor

def start_ping(net):
    # Start a ping train from h1 to h2 (or h2 to h1, does it
    # matter?)  Measure RTTs every 0.1 second.  Read the ping man page
    # to see how to do this.

    h1 = net.get('h1')
    h2 = net.get('h2')

    print("Starting ping train h1 -> h2")

    cmd = "ping -i 0.1 {} > {}/ping.txt".format(h2.IP(), args.dir)

    # Use host.popen(cmd, shell=True).  If you pass shell=True
    # to popen, you can redirect cmd's output using shell syntax.
    # i.e. ping ... > /path/to/ping.
    h1.popen(cmd, shell=True)

def start_webserver(net):
    h1 = net.get('h1')
    proc = h1.popen("python webserver.py", shell=True)
    sleep(1)
    return [proc]

def measure_time(net):
    h1 = net.get('h1')
    h2 = net.get('h2')

    # fetch the page 3 times and measure amount of time

    # record times
    times_record = []

    for x in range(3):
        # curl command
        # TODO: Check if correct path
        cmd = "curl -o /dev/null -s -w '%{{time_total}}\n' http://{}:80/index.html".format(h1.IP())
        # catch result
        result = h2.popen(cmd, shell=True, stdout=PIPE)
        # parse for output
        output = result.communicate()[0].decode().strip()
        curr_time = float(output)
        # record time
        times_record.append(curr_time)
        # wait for next download
        sleep(1)

    return times_record



def bufferbloat():
    if not os.path.exists(args.dir):
        os.makedirs(args.dir)
    os.system("sysctl -w net.ipv4.tcp_congestion_control=%s" % args.cong)
    topo = BBTopo()
    net = Mininet(topo=topo, host=CPULimitedHost, link=TCLink)
    net.start()
    # This dumps the topology and how nodes are interconnected through
    # links.
    dumpNodeConnections(net.hosts)
    # This performs a basic all pairs ping test.
    net.pingAll()

    # Start monitoring the queue sizes.  Since the switch I
    # created is "s0", I monitor one of the interfaces.  Which
    # interface?  The interface numbering starts with 1 and increases.
    # Depending on the order you add links to your network, this
    # number may be 1 or 2.  Ensure you use the correct number.
    qmon = start_qmon(iface='s0-eth2',
                      outfile='%s/q.txt' % (args.dir))

    # Start iperf, webservers, etc.
    start_iperf(net)

    # Start we server on h1
    start_webserver(net)

    # Start ping measurements
    start_ping(net)

    # measure the time it takes to complete webpage transfer
    # from h1 to h2 (say) 3 times.  Hint: check what the following
    # command does: curl -o /dev/null -s -w %{time_total} google.com
    # Now use the curl command to fetch webpage from the webserver you
    # spawned on host h1 (not from google!)
    # Hint: Verify the url by running your curl command without the
    # flags. The html webpage should be returned as the response.

    # Hint: have a separate function to do this and you may find the
    # loop below useful.

    all_times = []
    start_time = time()
    while True:
        # do the measurement (say) 3 times.
        curr_times = measure_time(net)
        # store measurements
        all_times.extend(curr_times)
        sleep(5)
        now = time()
        delta = now - start_time
        if delta > args.time:
            break
        print("%.1fs left..." % (args.time - delta))

    # compute average (and standard deviation) of the fetch
    # times.

    # average
    avg_time = statistics.mean(all_times)
    # std deviation
    std_dev_time = statistics.stdev(all_times)

    print(f"Average Time: {avg_time}")
    print(f"Standard Deviation: {std_dev_time}")

    # Hint: The command below invokes a CLI which you can use to
    # debug.  It allows you to run arbitrary commands inside your
    # emulated hosts h1 and h2.
    # CLI(net)

    qmon.terminate()
    net.stop()
    # Ensure that all processes you create within Mininet are killed.
    # Sometimes they require manual killing.
    Popen("pgrep -f webserver.py | xargs kill -9", shell=True).wait()

if __name__ == "__main__":
    bufferbloat()
