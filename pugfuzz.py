# Author: sunirge

from pydbg import *
from pydbg.defines import *

import utils
import random
import math
import thread
import time
import shutil
from datetime import datetime
import os
from os.path import join

crash_bin = utils.crash_binning.crash_binning()
timeout = 5
fuzzpercent = float(0.05) # percentage of file size bytes to fuzz
#formats = "" # current base file format
basefilename = list() # current base file name
basefiledir = "C:\\Python24\\jlpy\\bases" # directory for base files to fuzz
fuzzfiledir = "C:\\Python24\\jlpy\\fuzzes" # directory for temporary fuzzed base files
#fuzzfilename = list() # current fuzz file name
programname = "C:\\Program Files\\Tencent\\QQPlayer\\QQPlayer.exe" #change program name
crashname = "c:\\crashes\\crash"
crashsynop = "c:\\crashes\\crash_synop"

def av_handler (dbg):
	global crash_bin
	global basefilename
	global programname
        global fuzzfiledir
	crash_bin.record_crash(dbg)

	for ea in crash_bin.bins.keys():
		print "%d recorder crashes at %08x" % \
			(len(crash_bin.bins[ea]), ea)
	module = dbg.addr_to_module(dbg.context.Eip)
	if (module.szModule):
                print "Module name: " + module.szModule
        else:
                print "Module name: Unknown"
        if (module.szModule):
        	print "Module path: " + module.szExePath
        else:
                print "Module path: Unknown"
	thetime = datetime.now().strftime("%Y_%m_%d_%H_%M_%S")
	if (module.modBaseAddr):
                print "Module base address: %08x" % module.modBaseAddr
        else:
                print "Module base address: Unknown"
        if (module.hModule):
                print "Module hModule:      %08x" % module.hModule
        else:
                print "Module hModule:  Unknown"
        if (module.modBaseSize):
                print "Module size(bytes): " + str(module.modBaseSize)
        else:
                print "Module size(bytes): Unknown"
        if (module.modBaseAddr):
                crash_rva = "%08x" % (dbg.context.Eip - module.modBaseAddr)
        else:
                crash_rva= "%08x" % (dbg.context.Eip)
	print "Crash RVA: " + crash_rva
        try:
                if (module.szModule):
                        os.makedirs(crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0] + basefilename[1]) + "\\" + module.szModule + "\\" + crash_rva)
                else:
                        os.makedirs(crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0] + basefilename[1]) + "\\UnknownModule\\" + crash_rva)               
        except Exception:
                print "Couldn't make directories, or already exists"
                        

        try:
                if (module.szModule):
                        shutil.copyfile(fuzzfiledir + "\\" + os.path.basename(basefilename[0]) + "_fuzz" + basefilename[1] , crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0]+ basefilename[1]) + "\\" + module.szModule + "\\" + crash_rva  + "\\crash_" + thetime + basefilename[1])
                        print "Copied fuzz file to: " + crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0]+ basefilename[1]) + "\\" + module.szModule + "\\" + crash_rva  + "\\crash_" + thetime + basefilename[1]
                else:
                        shutil.copyfile(fuzzfiledir + "\\" + os.path.basename(basefilename[0]) + "_fuzz" + basefilename[1] , crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0]+ basefilename[1]) + "\\UnknownModule\\" + crash_rva  + "\\crash_" + thetime + basefilename[1])
                        print "Copied fuzz file to: " + crashname + "\\" + os.path.basename(programname) + "\\UnknownModule\\" + crash_rva  + "\\crash_" + thetime + basefilename[1]
        except IOError:
                print "Couldn't copy fuzzed filename to crash directory"

        try:
                if (module.szModule):
                        ag = open( crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0] + basefilename[1]) + "\\" + module.szModule + "\\" + crash_rva + "\\crash_synop_"+ thetime + ".txt", "w+")
                else:
                        ag = open( crashname + "\\" + os.path.basename(programname) + "\\" + os.path.basename(basefilename[0] + basefilename[1]) + "\\UnknownModule\\" + crash_rva + "\\crash_synop_"+ thetime + ".txt", "w+")

                ag.write(crash_bin.last_crash_synopsis())
                ag.close()
        except IOError:
                print "Couldn't write synopsis"
        try:
                if dbg.debugger_active:
                        dbg.terminate_process()
        except Exception:
                print "had some trouble terminating process"
	return DBG_CONTINUE

def ok(dbg):
        time.sleep(timeout)
        if dbg.debugger_active:
            dbg.terminate_process()
                
# MAIN ######################
basefiles = list()
for (dirpath, dirname, filenames) in os.walk(basefiledir):
    for name in filenames:
        a, b = os.path.splitext(join(dirpath,name))
        basefiles.append((a, b))

for i , j in basefiles:
        print i + " " + j

while 1:
        random.seed(time.time())
	dbg = pydbg()
	dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
	basefilename = basefiles[random.randrange(0, len(basefiles))]
        print "Base file: " + basefilename[0] + basefilename[1]
	
	f = open(basefilename[0] + basefilename[1], 'rb')
	buf = f.read()
	b = list(buf)
	f.close()

        numwrites=random.randrange(math.ceil((float(len(buf))) * fuzzpercent))+1
        for j in range(numwrites):
                rbyte = random.randrange(256)
        	rn = random.randrange(len(buf))
        	b[rn] = '%c'%(rbyte) 
        c=''.join(b)
        print "Changed %d bytes" % numwrites
        print "Fuzz file: " + fuzzfiledir + "\\" + os.path.basename(basefilename[0]) + "_fuzz" + basefilename[1]
        try:
            ff = open(fuzzfiledir + "\\" + os.path.basename(basefilename[0]) + "_fuzz" + basefilename[1], 'wb+')
            ff.write(c)
            ff.close()
        except IOError:
            print "Failed creating fuzzed file\n"
            continue
	thread.start_new_thread(ok, (dbg, ))

        dbg.load(programname, fuzzfiledir + "\\" + os.path.basename(basefilename[0]) + "_fuzz" + basefilename[1]) # you need to supply your arguments here
	dbg.run()
	time.sleep(0.5)
