# Author: sunirge

from pydbg import *
from pydbg.defines import *

import utils
import random
import math
import thread
import time
import shutil

crash_bin = utils.crash_binning.crash_binning()
i = 0
timeout = 4
fuzzpercent = float(0.05) # percentage of file size bytes to fuzz
format = ".avi"
basefilename = "C:\\Python24\\jlpy\\f.avi"
fuzzfilename = "C:\\Python24\\jlpy\\fuzz.avi"
programname = "C:\\Program Files\\" #change program name
crashname = "c:\\crashes\\crash"
crashsynop = "c:\\crashes\\crash_synop"

def av_handler (dbg):
	global crash_bin
	crash_bin.record_crash(dbg)

	for ea in crash_bin.bins.keys():
		print "%d recorder crashes at %08x" % \
			(len(crash_bin.bins[ea]), ea)
        global i
        shutil.copyfile(fuzzfilename, crashname + str(i) + format)
        ag = open( crashsynop + str(i) + ".txt", "w+")
        i = i + 1
        ag.write(crash_bin.last_crash_synopsis())
        ag.close()
	dbg.terminate_process()
	return DBG_CONTINUE

def ok(dbg):
        time.sleep(timeout)
        if dbg.debugger_active:
            dbg.terminate_process()
                

while 1:
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
	f = open(basefilename, 'rb')
	buf = f.read()
	b = list(buf)
	f.close()
        random.seed(time.time())
        numwrites=random.randrange(math.ceil((float(len(buf))) * fuzzpercent))+1
        for j in range(numwrites):
                rbyte = random.randrange(256)
        	rn = random.randrange(len(buf))
        	b[rn] = '%c'%(rbyte) 
        c=''.join(b)
        try:
            ff = open(fuzzfilename, 'wb+')
            ff.write(c)
            ff.close()
        except IOError:
            print "Failed creating fuzzed file\n"
            continue
	thread.start_new_thread(ok, (dbg, ))

        dbg.load(programname, fuzzfilename) # you need to supply your arguments here
	dbg.run()
	time.sleep(0.5)

