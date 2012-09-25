# Author: sunirge

import utils
import random
import math
import thread
import time
import shutil
from datetime import datetime
import os
import subprocess
from os.path import join

crash_bin = utils.crash_binning.crash_binning()
timeout = 5
fuzzpercent = float(0.05) # percentage of file size bytes to fuzz
#formats = "" # current base file format
basefilename = list() # current base file name
basefiledir = "C:\\Python24\\bases" # directory for base files to fuzz
fuzzfiledir = "C:\\Python24\\fuzzes" # directory for temporary fuzzed base files
#fuzzfilename = list() # current fuzz file name
cdblocation = "C:\\Program Files\\Windows Kits\\8.0\\Debuggers\\x86\\cdb.exe"
programname = "" #change program name
msecloc = "C:\\Program Files\\Windows Kits\\8.0\\Debuggers\\x86\\winext"
crashdir = "c:\\crashes\\crash"
                
# MAIN ######################
basefiles = list()
for (dirpath, dirname, filenames) in os.walk(crashdir):
    for name in filenames:
        if not name.endswith(".txt"):
                a, b = os.path.splitext(join(dirpath,name))
                basefiles.append((a, b))

for i , j in basefiles:
        strs = "\""+cdblocation + "\"" + " -g -c \".symfix+; .reload; !load msec.dll; .logopen \""+ i +"_classification.log\"; !exploitable -m; .logclose; q\" -a\"" + msecloc + "\" \"" + programname + "\" \"" + i + j + "\""
        subprocess.call(strs)
        
#strs = "\""+cdblocation + "\"" + " -g -c \".symfix+; .reload; !load msec.dll; .logopen \""+basefiles[0][0]+"_classification.log\"; !exploitable -m; .logclose; q\" -a\"" + msecloc + "\" \"" + programname + "\" \"" + basefiles[0][0] + basefiles[0][1] + "\""
#print basefiles[0][0] + basefiles[0][1]
#print strs

#subprocess.call(strs)
