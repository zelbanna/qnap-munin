#!/usr/bin/python
# -*- coding: utf-8 -*-

"""Program docstring.

Application to create a munin server to provide fetch and config for different "plugins"
- Threaded 
- Each client socket is passed as argument
- Special case is "dual" _ (e.g. eth interfaces)

"""
__author__ = "Zacharias El Banna"
__version__ = "2.0"
__status__ = "Production"

import sys
import time
from socket import *
from thread import *
from subprocess import check_output

if len(sys.argv) < 3:
 print sys.argv[0] + " <name to advertise> <ntp peer> <raid volume>"
 sys.exit(1)

HOSTNAME = sys.argv[1]
NTPHOST = sys.argv[2]
VOLDISK = sys.argv[3]
HOST = ''   # Symbolic name meaning all available interfaces
PORT = 4949 # Arbitrary non-privileged port
VERSION = "2.0"

# Make dictionary
PLUGINS=[]
PLUGINSLIST = [ 'processes', 'df', 'ntpdate', 'if_', 'uptime', 'swap', 'load', 'cpu', 'memory', 'temp', 'fanspeed', 'disktemp', 'diskuse' ]

################################ PLUGINS #################################
#
# Each plugin needs to be: A) added to PLUGINS list and B) have a
# fetch_ and config_ function defined for it. Both functions will get a
# connection entity as parameter which it can use "sendall" from to send
# output to client
#

#
# Diskuse
#
def config_diskuse(conn):
 conn.sendall("multigraph diskuse_ops\n"
  "graph_title Disk operations\n"
  "graph_args --base 1000 --vertical-label Operations\n"
  "graph_category disk\n"
  "mdreads.label " + VOLDISK + " reads\n"
  "mdreads.type COUNTER\n"
  "mdwrits.label "+ VOLDISK +" Writes\n"
  "mdwrits.type COUNTER\n"
  "\n"
  "multigraph diskuse_bytes\n"
  "graph_title Disk Bytes operations\n"
  "graph_args --base 1024 --vertical-label Bytes\n"
  "graph_category disk\n"
  "mdreadb.label " + VOLDISK + " read bytes\n"
  "mdreadb.type COUNTER\n"
  "mdwritb.label " + VOLDISK + " write bytes\n"
  "mdwritb.type COUNTER\n")

def fetch_diskuse(conn):
 sectorsize = int(check_output(["cat","/sys/block/" + VOLDISK + "/queue/hw_sector_size"]))
 diskstats = check_output(["grep",VOLDISK,"/proc/diskstats"]).split()
 conn.sendall("multigraph diskuse_ops\n"
  "mdreads.value " + diskstats[3] + "\n"
  "mdwrits.value " + diskstats[7] + "\n"
  "\n"
  "multigraph diskuse_bytes\n"
  "mdreadb.value " + str(int(diskstats[5]) * sectorsize) + "\n"
  "mdwritb.value " + str(int(diskstats[9]) * sectorsize) + "\n")
 
#
# Disktemp
#

def config_disktemp(conn):
 conn.sendall("graph_title Disk Temperatures\n"
  "graph_args --base 1000 -l 20 -u 60 --vertical-label temp\n"
  "graph_scale no\n"
  "graph_category temp\n")
 disks = check_output(["getsysinfo","hdnum"])
 for disk in range(1, int(disks)+1):
  status = check_output(["getsysinfo","hdstatus",str(disk)]).strip('\n')
  if status == "0":
   name = check_output(["getsysinfo","hdmodel",str(disk)]).strip('\n')
   conn.sendall("slot"+str(disk)+".label Slot " + str(disk) + "\n"
    "slot"+str(disk)+".info Slot " + name + "\n")


def fetch_disktemp(conn):
 disks = check_output(["getsysinfo","hdnum"])
 for disk in range(1, int(disks)+1):
  try:
   temp = check_output(["/sbin/get_hd_temp",str(disk)]).strip('\n')
   if not temp == "none": 
    conn.sendall("slot" + str(disk) + ".value " + temp + "\n")
   else:
    status = check_output(["getsysinfo","hdstatus",str(disk)]).strip('\n')
    if status == "0":
     conn.sendall("slot" + str(disk) + ".value U\n")
  except Exception as err:
   continue
#
# Fanspeed
#

def config_fanspeed(conn):
 conn.sendall("graph_title Fan Speeds\n"
  "graph_args --base 1000 -u 2000 -l 200 --vertical-label RPM\n"
  "graph_scale no\n"
  "graph_category system\n")
 fans = check_output(["getsysinfo","sysfannum"])
 for fan in range(1, int(fans)+1):
  conn.sendall("fan" + str(fan) + ".label Fan " + str(fan) +"\n"
   "fan" + str(fan) + ".info System fan\n")

def fetch_fanspeed(conn):
 fans = check_output(["getsysinfo","sysfannum"])
 for fan in range(1, int(fans)+1):  
  rpm = check_output(["getsysinfo","sysfan",str(fan)])
  conn.sendall("fan" + str(fan) + ".value " + str(rpm) +"\n")

#
# Temp
#
def config_temp(conn):
 conn.sendall("graph_title System Temperature (Celsius)\n"
  "graph_args --base 1000 -u 100 -l 0\n"
  "graph_vlabel Temp\n"
  "graph_scale no\n"
  "graph_category system\n"
  "cputemp.label CPU temp\n"
  "systemp.label SYS temp\n"
  "graph_info The temperature of the system\n")

def fetch_temp(conn):
 cputmp = check_output(["getsysinfo","cputmp"])
 systmp = check_output(["getsysinfo","systmp"])
 conn.sendall("cputemp.value " + cputmp.split()[0] + "\n")
 conn.sendall("systemp.value " + systmp.split()[0] + "\n")

#
# Memory
#

def config_memory(conn):
 data = check_output(["cat","/proc/meminfo"])
 memtotal = data.split(None,2)[1]
 graphorder="apps"

 conn.sendall("graph_args --base 1024 -l 0 --vertical-label Bytes --upper-limit " + memtotal + "\n"
  "graph_title Memory usage\n"
  "graph_category memory\n"
  "graph_info This graph shows what the machine uses its memory for.\n"
  "apps.label apps\n"
  "apps.draw AREA\n"
  "apps.info Memory used by user-space applications.\n"
  "buffers.label buffers\n"
  "buffers.draw STACK\n"
  "buffers.info Block device (e.g. harddisk) cache. Also where dirty blocks are stored until written.\n"
  "swap.label swap\n"
  "swap.draw STACK\n"  
  "swap.info Swap space used.\n"
  "cached.label cache\n"
  "cached.draw STACK\n"
  "cached.info Parked file data (file content) cache.\n"
  "free.label unused\n"
  "free.draw STACK\n"
  "free.info Wasted memory. Memory that is not used for anything at all.\n")

 for line in data.split('\n'):
  if "PageTables:" in line:
   graphorder = graphorder + " page_tables"
   conn.sendall("page_tables.label page_tables\n"
    "page_tables.draw STACK\n"
    "page_tables.info Memory used to map between virtual and physical memory addresses.\n")
  elif "SwapCached:" in line:
   graphorder = graphorder + " swap_cache"
   conn.sendall("swap_cache.label swap_cache\n"
    "swap_cache.draw STACK\n"
    "swap_cache.info A piece of memory that keeps track of pages that have been fetched from swap but not yet been modified.\n")
  elif "Slab:" in line:
   graphorder = graphorder + " slab"
   conn.sendall("slab.label slab\n"
    "slab.draw STACK\n"
    "slab.info Memory used by the kernel (major users are caches like inode, dentry, etc).\n")
  elif "VmallocUsed:" in line:
   # graphorder = graphorder + " vmalloc_used"
   conn.sendall("vmalloc_used.label vmalloc_used\n"
    "vmalloc_used.draw LINE2\n"
    "vmalloc_used.info Virtual memory used by the kernel (used when the memory does not have to be physically contigious).\n")
  elif "Committed_AS:" in line:
   conn.sendall("committed.label committed\n"
    "committed.draw LINE2\n"
    "committed.info The amount of memory that would be used if all the memory that's been allocated were to be used.\n")
  elif "Mapped:" in line:
   conn.sendall("mapped.label mapped\n"
    "mapped.draw LINE2\n"
    "mapped.info All mmap()ed pages.\n")   
  elif "Active:" in line:
   conn.sendall("active.label active\n"
    "active.draw LINE2\n"
    "active.info Memory recently used. Not reclaimed unless absolutely necessary.\n")
  elif "ActiveAnon:" in line:
   conn.sendall("active_anon.label active_anon\n"
    "active_anon.draw LINE1\n")
  elif "ActiveCache:" in line:
   conn.sendall("active_cache.label active_cache\n"
    "active_cache.draw LINE1\n")
  elif "Inactive:" in line:
   conn.sendall("inactive.label inactive\n"
    "inactive.draw LINE2\n"
    "inactive.info Memory not currently used.\n")
  elif "Inact_dirty:" in line:
   conn.sendall("inact_dirty.label inactive_dirty\n"
    "inact_dirty.draw LINE1\n"
    "inact_dirty.info Memory not currently used, but in need of being written to disk.\n")
  elif "Inact_laundry:" in line:
   conn.sendall("inact_laundry.label inactive_laundry\n"
    "inact_laundry.draw LINE1\n")
  elif "Inact_clean:" in line:
   conn.sendall("inact_clean.label inactive_clean\n"
   "inact_clean.draw LINE1\n"
   "inact_clean.info Memory not currently used.\n")

 conn.sendall("graph_order " + graphorder + " cached buffers free swap\n")

def fetch_memory(conn):
 data = check_output(["cat","/proc/meminfo"])

 memtotal = 0
 memfree = 0
 buffers = 0
 cached = 0
 swaptotal = 0
 swapfree = 0
 swapcached = 0
 pagetables = 0
 slab = 0
 vmallocused = 0
 
 for line in data.split('\n'):
  linelist = line.split()
  if "MemTotal:" in line:
   memtotal = int(linelist[1])
  elif "PageTables:" in line:
   pagetables = int(linelist[1])
   conn.sendall("page_tables.value " + str(pagetables*1024) + "\n")   
  elif "MemFree:" in line:
   memfree = int(linelist[1])
   conn.sendall("free.value " + str(memfree*1024) + "\n")
  elif "Buffers:" in line:
   buffers = int(linelist[1])
   conn.sendall("buffers.value " + str(buffers*1024) + "\n")
  elif "SwapCached:" in line:
   swapcached = int(linelist[1]) 
   conn.sendall("swap_cache.value " + str(swapcached*1024) + "\n")
  elif "Cached:" in line:
   cached = int(linelist[1])
   conn.sendall("cached.value " + str(cached*1024) + "\n")    
  elif "SwapTotal:" in line:
   swaptotal = int(linelist[1])
  elif "SwapFree:" in line:
   swapfree = int(linelist[1])
  elif "Slab:" in line:
   slab = int(linelist[1])
   conn.sendall("slab.value " + str(slab*1024) + "\n")
  elif "VmallocUsed:" in line:
   vmallocused = int(linelist[1])
   conn.sendall("vmalloc_used.value " + str(vmallocused*1024) + "\n")   
  elif "Committed_AS:" in line:
   committed = int(linelist[1])
   if committed > memtotal:
    conn.sendall("committed.value U\n")    
   else:
    conn.sendall("committed.value " + str(committed*1024) + "\n")
  elif "Mapped:" in line:
   conn.sendall("mapped.value " + str(int(linelist[1])*1024) + "\n")
  elif "Active:" in line:
   conn.sendall("active.value " + str(int(linelist[1])*1024) + "\n")
  elif "ActiveAnon:" in line:
   conn.sendall("active_anon.value " + str(int(linelist[1])*1024) + "\n")
  elif "ActiveCache:" in line:
   conn.sendall("active_cache.value " + str(int(linelist[1])*1024) + "\n")
  elif "Inactive:" in line:
   conn.sendall("inactive.value " + str(int(linelist[1])*1024) + "\n")
  elif "Inact_dirty:" in line:
   conn.sendall("inact_dirty.value " + str(int(linelist[1])*1024) + "\n")
  elif "Inact_laundry:" in line:
   conn.sendall("inact_laundry.value " + str(int(linelist[1])*1024) + "\n")
  elif "Inact_clean:" in line:
   conn.sendall("inact_clean.value " + str(int(linelist[1])*1024) + "\n")

 swap = swaptotal - swapfree
 conn.sendall("swap.value " + str(swap*1024) + "\n")
 appstotal = memtotal - (memfree + buffers + cached + slab + swapcached + pagetables)
 conn.sendall("apps.value " + str(int(appstotal)*1024) + "\n")
                                                                     

#
# CPU
#

def config_cpu(conn):
 extinfo=""
 try:
  # Check output will throw exception if empty output..
  layout = check_output("grep '^cpu \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\}' /proc/stat", shell=True)
  extinfo = " iowait irq softirq"
 except Exception as err:
  extinfo = ""

 ncpu=int(check_output("grep '^cpu. ' /proc/stat | wc -l", shell=True))
 if ncpu == 0:
  percent=100
 else:
  percent=(ncpu-1)*100
 graphlimit= percent
 syswarning= percent * 30 / 100
 syscritical=percent * 50 / 100
 usrwarning= percent * 80 / 100
 
 conn.sendall("graph_title CPU usage\n"
  "graph_order system user nice idle" + extinfo + "\n"
  "graph_args --base 1000 -r --lower-limit 0 --upper-limit " + str(graphlimit) + "\n"
  "graph_vlabel %\n"
  "graph_scale no\n"
  "graph_info This graph shows how CPU time is spent.\n"
  "graph_category processing\n"
  "graph_period second\n"
  "system.label system\n"
  "system.draw AREA\n"
  "system.max 5000\n"
  "system.min 0\n"
  "system.type DERIVE\n"
  "system.warning " + str(syswarning) + "\n"
  "system.critical " + str(syscritical) + "\n"
  "system.info CPU time spent by the kernel in system activities\n")
 conn.sendall("user.label user\n"
  "user.draw STACK\n"
  "user.min 0\n"
  "user.max 5000\n"
  "user.warning " + str(usrwarning) + "\n"
  "user.type DERIVE\n"
  "user.info CPU time spent by normal programs and daemons\n"
  "nice.label nice\n"
  "nice.draw STACK\n"
  "nice.min 0\n"
  "nice.max 5000\n"
  "nice.type DERIVE\n"
  "nice.info CPU time spent by nice(1)d programs\n"
  "idle.label idle\n"
  "idle.draw STACK\n"
  "idle.min 0\n"
  "idle.max 5000\n"
  "idle.type DERIVE\n"
  "idle.info Idle CPU time\n")
 if not extinfo is "":
  conn.sendall("iowait.label iowait\n"
   "iowait.draw STACK\n"
   "iowait.min 0\n"
   "iowait.max 5000\n"
   "iowait.type DERIVE\n"
   "iowait.info CPU time spent waiting for I/O operations to finish\n"
   "irq.label irq\n"
   "irq.draw STACK\n"
   "irq.min 0\n"
   "irq.max 5000\n"
   "irq.type DERIVE\n"
   "irq.info CPU time spent handling interrupts\n"
   "softirq.label softirq\n"
   "softirq.draw STACK\n"
   "softirq.min 0\n"
   "softirq.max 5000\n"
   "softirq.type DERIVE\n"
   "softirq.info CPU time spent handling batched interrupts\n")

def fetch_cpu(conn):
 extinfo=""
 try:
  # Check output will throw exception if empty output..
  layout = check_output("grep '^cpu \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\} \{1,\}[0-9]\{1,\}' /proc/stat", shell=True)
  extinfo = " iowait irq softirq"
 except Exception as err:
  extinfo = ""
 cline=check_output("grep '^cpu ' /proc/stat", shell=True)
 cinfo=cline[6:].split()
 conn.sendall("user.value " + cinfo[0] + "\n"
  "nice.value " + cinfo[1] + "\n"
  "system.value " + cinfo[2] + "\n"
  "idle.value " + cinfo[3] + "\n")
 if not extinfo is "":
  conn.sendall("iowait.value " + cinfo[4] + "\n"
   "irq.value " + cinfo[5] + "\n"
   "softirq.value " + cinfo[6] + "\n")
 
#
# Load
#
def config_load(conn):
 conn.sendall("graph_title Load average\n"
  "graph_args --base 1000 -l 0\n"
  "graph_vlabel load\n"
  "graph_scale no\n"
  "graph_info The load average of the machine describes how many processes are in the run-queue (scheduled to run immediately).\n"
  "graph_category processing\n"
  "load.label load\n"
  "load.warning 10\n"
  "load.critical 120\n"
  "load.info Average load for the five minutes.\n")

def fetch_load(conn):
 data = check_output(["cat","/proc/loadavg"])
 conn.sendall("load.value " + data.split()[1] + "\n")

#
# Swap
#
def config_swap(conn):
 conn.sendall("graph_title Swap in/out\n"
  "graph_args -l 0 --base 1000\n"
  "graph_vlabel pages per ${graph_period} in (-) / out (+)\n"
  "graph_category memory\n"
  "swap_in.label swap\n"
  "swap_in.type DERIVE\n"
  "swap_in.max 100000\n"
  "swap_in.min 0\n"
  "swap_in.graph no\n"
  "swap_out.label swap\n"
  "swap_out.type DERIVE\n"
  "swap_out.max 100000\n"
  "swap_out.min 0\n"
  "swap_out.negative swap_in\n")

def fetch_swap(conn):
 data = check_output(["cat","/proc/vmstat"])
 for line in data.split('\n'):
  if "pswpin" in line:
   conn.sendall("swap_in.value " + line.split()[1] + "\n")
  elif "pswpout" in line:
   conn.sendall("swap_out.value " + line.split()[1] + "\n")

#
# Uptime
#
def config_uptime(conn):
 conn.sendall("graph_title Uptime\n"
  "graph_args --base 1000 -l 0\n"
  "graph_vlabel uptime in days\n"
  "graph_category system\n"
  "uptime.label uptime\n"
  "uptime.draw AREA\n"
  "uptime.cdef uptime,86400,/\n")

def fetch_uptime(conn):
 data = check_output(["cat","/proc/uptime"])
 conn.sendall("uptime.value " + data.split()[0] + "\n")

#
# Processes plugin
# 
def config_processes(conn):
 conn.sendall("graph_title Number of Processes\n"
  "graph_args --base 1000 -l 0\n"
  "graph_vlabel number of processes\n"
  "graph_category processing\n"
  "graph_info This graph shows the number of processes in the system.\n"
  "processes.label processes\n"
  "processes.draw LINE2\n"
  "processes.info The current number of processes.\n")

def fetch_processes(conn):
 res = check_output("echo /proc/[0-9]* | wc -w", shell=True).strip()
 conn.sendall("processes.value " + res + "\n")

#
# Disk usage
#
def config_df(conn):
 conn.sendall("graph_title Filesystem usage (in %)\n"
  "graph_vlabel %\n"
  "graph_category disk\n"
  "graph_info This graph shows disk usage on the machine.\n")
 partitions = check_output("df -c -h | grep -E '^/.*DATA$|/tmp'", shell=True)
 for part in partitions.split('\n'):
  if not part is "":
   partlist = part.split()
   partname = partlist[0].replace('/','_').replace('.','_').replace('-','_')
   conn.sendall(partname + ".label " + partlist[5] + "\n")
   conn.sendall(partname + ".info " + partlist[0] + " -> " + partlist[5] + "\n")

def fetch_df(conn):
 partitions = check_output("df -c -h | grep -E '^/.*DATA$|/tmp'", shell=True)
 for part in partitions.split('\n'):
  if not part is "":
   partlist = part.split()
   partname = partlist[0].replace('/','_').replace('.','_').replace('-','_')
   conn.sendall(partname + ".value " + partlist[4].strip("%") + "\n")

#
# NTPdate
#

def config_ntpdate(conn):
 global NTPHOST
 conn.sendall("graph_title NTP offset and delay to peer " + NTPHOST + "\n"
  "graph_args --base 1000 --vertical-label msec\n"
  "graph_category system\n"
  "offset.label Offset\n"
  "offset.draw LINE2\n"
  "delay.label Delay\n"
  "delay.draw LINE2\n")
            
def fetch_ntpdate(conn):
 global NTPHOST
 try:
  data = check_output("ntpdate -q " + NTPHOST + " 2>&1", shell=True)
  for line in data.split('\n'):
   if line is not "" and line[0:6] == 'server':
    linelist = line.replace(',','').split()
    delay  = float(linelist[7])*1000
    offset = float(linelist[5])*1000
    conn.sendall("delay.value " + str(delay) + "\n"
     "offset.value " + str(offset) + "\n")
 except Exception as err:
  return

#
# IF_
#

def config_if(conn , arg):
 conn.sendall("graph_order down up\n"
  "graph_title " + arg + " traffic\n"
  "graph_args --base 1000\n"
  "graph_vlabel bits in (-) / out (+) per ${graph_period}\n"
  "graph_category network\n"
  "graph_info This graph shows the traffic of the " + arg + " network interface. Please note that the traffic is shown in bits per second, not bytes. IMPORTANT: Since the data source for this plugin use 32bit counters, this plugin is really unreliable and unsuitable for most 100Mb (or faster) interfaces, where bursts are expected to exceed 50Mbps. This means that this plugin is usuitable for most production environments. To avoid this problem, use the ip_ plugin instead.\n"
  "down.label received\n"
  "down.type DERIVE\n"
  "down.min 0\n"
  "down.graph no\n"
  "down.cdef down,8,*\n"
  "up.label bps\n"
  "up.type DERIVE\n"
  "up.min 0\n"
  "up.negative down\n"
  "up.cdef up,8,*\n")
 data = check_output("ethtool " + arg, shell=True)
 found = False
 for line in data.split('\n'):
  if line is not "" and not "Unknown" in line and "Speed:" in line:
   found = True
   rate = line[line.find("Speed: ")+7:line.find("Mb/s")]
   conn.sendall("up.max "   + rate + "000000\n")
   conn.sendall("down.max " + rate + "000000\n")
 if not found:
  conn.sendall("up.max 1000000000\n")
  conn.sendall("down.max 1000000000\n")

def fetch_if(conn,arg):
 data = check_output("cat /proc/net/dev", shell=True)
 for devline in data.split('\n'):
  if arg in devline:
   devlist = devline.split()
   conn.sendall("down.value " + devlist[1] + "\n")
   conn.sendall("up.value " + devlist[9] + "\n")

############################### Main Loop ################################
#
#

def createPlugins():
 global PLUGINS
 for plugin in PLUGINSLIST:
  # Assumes < 10 eth interfaces...
  if plugin == "if_":
   data = check_output("cat /proc/net/dev", shell=True)
   for devline in data.split('\n'):
    indx = devline.find("eth")
    if indx > 0:
     # .. Other option would be to find ":" here and use as end
     PLUGINS.append("if_" + devline[indx:indx+4])
  else :
   PLUGINS.append(plugin)

def muninThread(conn,addr):
 global HOSTNAME
 global VERSION
 global PLUGINS
 conn.send('# munin node at ' + HOSTNAME + '\n')
 try:
  while True:
   data = conn.recv(1024)
   args = data.strip('\r\n').split(' ')
   # print "Got args: " + str(args)
   if   args[0] == 'quit':
    break
   elif args[0] == 'version':
    conn.sendall("munins node on " + HOSTNAME + " version: " + VERSION + "\n")
   elif args[0] == 'nodes':
    conn.sendall(HOSTNAME + "\n.\n")
   elif args[0] == 'list':
    conn.sendall(" ".join(PLUGINS) + "\n")
   elif args[0] == 'fetch' or args[0] == 'config':
    if len(args) == 1:
     conn.sendall("# Unknown service\n")
    elif not args[1] in PLUGINS:
     conn.sendall("# Unknown service\n")
    else:
     # Test for dual _ to find function + argument
     indx = args[1].find("_")
     if indx < 0:
      fun = args[0] + "_" + args[1]
      globals()[fun](conn)
     else:
      fun = args[0] + "_" + args[1][0:indx]
      arg = args[1][indx+1:]
      globals()[fun](conn,arg)
     conn.sendall(".\n")
   else:
    conn.sendall("# Unknown command, try one of: list, nodes, config, fetch, version or quit\n")
  conn.close()
 except Exception as errmsg:
  print 'Munin thread error: ' + str(errmsg)

def singleServer():
 server = socket(AF_INET, SOCK_STREAM)
 server.setsockopt(SOL_SOCKET, SO_REUSEADDR, 1)
 try:
  # Also emit syslog message to log server to acknowledge new server?
  server.bind((HOST, PORT))
  server.listen(5)
 except socket.error as msg:
  print 'Bind failed. Error Code : ' + str(msg)
  return None

 while True:
  conn, addr = server.accept()
  start_new_thread(muninThread, (conn,addr))
 server.close()

class DebugClass:
 """ A dummy class for dev and debug with conn objects :-) """

 def sendall(self, arg):
  print arg.rstrip('\n')

######################################################################

if __name__ == "__main__":
 createPlugins()
 singleServer()
 #con = DebugClass()
 #config_disktemp(con)
 #print "----------"
 #fetch_disktemp(con)

