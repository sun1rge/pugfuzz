from pydbg import *
from pydbg.defines import *

import utils
import random
import math
import thread
import time
import shutil
import os


orig_eip=None
crash_eip=None
basefile = "c:\\Python24\\12.3gp"
fuzzfile = "c:\\crashes\\3gpcrash2best_reduced.3gp"
reducedfile = "c:\\crashes\\3gpcrash3"
extension = ".3gp"
#like = "0000d29e" #RVA needed
instr = "rep movsb" #Actual instruction
modulename = "swscale-0.dll"  # original crash module name
curmodname = ""
programname = ""
newbugsdir = "c:\\crashes\\newbugs"
basebuff = None
timeout = 5
initial = 1
crash_bin = utils.crash_binning.crash_binning()
d_asm = None

def av_handler (dbg):
    global initial
    global crash_eip
    global orig_eip #RVA from module base
    global modulename
    global crash_bin
    global d_asm
    global curmodname
    
    print "CRASHED AT %08x" % dbg.context.Eip
    print "DISASM:"
    print dbg.disasm(dbg.context.Eip)
    module = dbg.addr_to_module(dbg.context.Eip)
    print "MODULE NAME: " + module.szModule
    print "MODULE BASE ADDR: %08x" % module.modBaseAddr
    print "MODULE HANDLE: %08x" % module.hModule
    print "DIFFERENCE: %08x" % (dbg.context.Eip - module.modBaseAddr)
    
    if (initial):
        orig_eip = (dbg.context.Eip - module.modBaseAddr)
        modulename = module.szModule
        print "hello"
        initial = 0
    else:
        crash_eip = (dbg.context.Eip - module.modBaseAddr)
        curmodname = module.szModule
        print "ORIGINAL AT %08x" % orig_eip
        d_asm = dbg.disasm(dbg.context.Eip)
        #if (crash_eip != orig_eip): #add new crashes, threshold
        if (crash_eip !=  orig_eip and (modulename != module.szModule)):
            crash_bin.record_crash(dbg)
            print crash_bin.crash_synopsis()

    try:
        dbg.terminate_process()
    except Exception:
        print "TRIED TO TERMINATE PROCESS, EXCEPTION"
    return DBG_CONTINUE

def watc(dbg):
    time.sleep(timeout)
    if dbg.debugger_active:
        dbg.terminate_process()
                
def reducef(fbuf, curmax, cur):
    global crash_eip
    global orig_eip
    global basebuff
    global extension
    global reducedfile
    global modulename
    global curmodname
#    global like
    global d_asm

    j = 0
    reducedbuf = fbuf
    
    for i in range(len(basebuff)):
        if (basebuff[i] != reducedbuf[i]):
            j+=1
            print "iteration: " + str(j)
            print "changing byte: 0x%02x" % ord(reducedbuf[i])
            print "to byte: 0x%02x" % ord(basebuff[i])
            #savedbyte = reducedbuf[i]
            savedbuff = reducedbuf
            print "at i: " + str(i)
            print "cur: " + str(cur)
            fr = list(reducedbuf)
            fr[i] = basebuff[i]
            oo = ''.join(fr)
            
            print "writing to file: " + reducedfile + str(cur) +  extension
            try:
                g = open(reducedfile + str(cur) + extension, "wb+")
                g.write(oo)
                g.close()
            except IOError:
                print "Couldn't write to new file"
                pass
            
            print "Trying it out with pydbg"
            dbg = pydbg()
            dbg.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
            thread.start_new_thread(watc, (dbg, ))

            dbg.load(programname, reducedfile + str(cur) + extension)
            try:
                dbg.run()
            except MemoryError:
                print "Some memory error exception!"
                crash_eip = None
                d_asm = None
                #fr = list(reducedbuf)
                #fr[i] = savedbyte
                #reducedbuf = ''.join(fr)
                reducedbuf = savedbuff
                try:
                    os.remove(reducedfile + str(cur) + extension)
                except Exception:
                    pass
                continue

            #IF crash is good, use same buffer to reduce more, else continue to next byte
           # if (crash_eip == orig_eip): # add threshold
            if (crash_eip):
                print "hex: " + "%08x" % crash_eip 
                #print "like: " + like
                if (d_asm):
                    print "asm: " + d_asm
                print "instr: " + instr
                
            #if (crash_eip and ((crash_eip == orig_eip) or (("%08x" % crash_eip).endswith(like) and d_asm == instr))):
            if (crash_eip and ((crash_eip == orig_eip) and (d_asm == instr) and (modulename == curmodname))):    #also check for the module name
                print "crash eip IS same as original crash eip\n"
                cur+=1
                crash_eip=None
                d_asm = None
                try:
                    f = open(reducedfile + "best_reduced" + extension, 'wb+')
                    print "writing best reduced case"
                    f.write(oo)
                    f.close()
                except IOError:
                    print "Failed to write best reduced file\n"
                    pass
                reducedbuf = oo
                try:
                    os.remove(reducedfile + str(cur-1) + extension)
                except Exception:
                    pass
                #reducef(oo, curmax, cur)
            else:
                print "crash eip IS NOT the same as original eip,reverting"
                #fr = list(reducedbuf)
                #fr[i] = savedbyte
                #reducedbuf = ''.join(fr)
                reducedbuf = savedbuff
                try:
                    print "new crash was at %08x: " % crash_eip
                except TypeError:
                    pass
                    
                try:
                    os.remove(reducedfile + str(cur) + extension)
                except Exception:
                    pass
                crash_eip = None
                d_asm=None
    print "Changed bytes: " + str(cur)
                
############### MAIN ####################
global basebuff
global initial
global orig_eip
global reducedfile
fuzzbuff=None

try:
    f = open(basefile, 'rb')
    basebuff = f.read()
    f.close()
except IOError:
    print "Failed to read base file\n"
    exit()

try:
    ff = open(fuzzfile, 'rb')
    df = open(reducedfile, 'wb+')
    fuzzbuff = ff.read()
    df.write(fuzzbuff)
    ff.close()
    df.close()
except IOError:
    print "Failed to read fuzzed file\n"
    exit()
    
db = pydbg()
db.set_callback(EXCEPTION_ACCESS_VIOLATION, av_handler)
thread.start_new_thread(watc, (db, ))
db.load(programname, fuzzfile)
db.run()
#print "eip is %08x" % orig_eip
if (orig_eip != None):
    print "original crash eip is %08x: " % orig_eip
    print "Reducing file..."
    count=0
    for i in range(len(basebuff)):
        if (basebuff[i] != fuzzbuff[i]):
           count +=1
    print "There are " + str(count) + " different bytes from the base and the fuzzed"
    reducef(fuzzbuff, 0, 0)
else:
    print "Fuzzed file did not crash within timeout\n"
    exit()
