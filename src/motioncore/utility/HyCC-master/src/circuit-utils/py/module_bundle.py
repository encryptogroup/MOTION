#!/usr/bin/python
__author__ = "Daniel Demmler (demmler@encrypto.cs.tu-darmstadt.de)"
__copyright__ = "Copyright (C) 2019 Daniel Demmler"
__license__ = "AGPL 3.0"
__version__ = "0.2"

import sys
import os
from pathlib import Path

verbose = True

def main():
	print("HyCC Module Bundle Generator v" + __version__)
	if(len(sys.argv) != 2):
		print("Error: Please specify a directory full of CBMC/HyCC circuit modules (*.circ)")
		exit(0)

	# append supplied path to currend directory
	dirname = Path.cwd() / Path(sys.argv[1])

	print("Directory:", dirname)
	os.chdir(dirname)

	circlist = []
	circdir = {}

	# collect all files ending with ".circ" that also have an "@" in the name, ignore everything else
	for f in os.listdir(dirname):
		if f.endswith(".circ") and "@" in f:
			circlist.append(f)
			if verbose: print("found "+ f)
		else:
			if verbose: print("(ignoring "+ f + ")")

	if not circlist:
		print("Error: Please specify a directory full of CBMC/HyCC circuit modules (*.circ). None were found.")
		exit(0)

	# for every circuit module file
	for c in circlist:
		cs = c.split("@")
		circdir.setdefault(cs[0], []).append(cs[1]) # (if module does not exist, create empty list) append type

	with open("all.cmb", "w") as of:
		for c in circlist:
			of.write(c+"\n")

	with open("yaoonly.cmb", "w") as of:
		for c in circdir:
			if "bool_size.circ" in circdir[c]:
				of.write(c+"@bool_size.circ"+"\n")
			else:
				print("Cannot build Yao only version of this circuit!")
				break

	with open("gmwonly.cmb", "w") as of:
		for c in circdir:
			if "bool_depth.circ" in circdir[c]:
				of.write(c+"@bool_depth.circ"+"\n")
			else:
				print("Cannot build GMW only version of this circuit!")
				break

	with open("gmwhybrid.cmb", "w") as of:
		for c in circdir:
			if "arith.circ" in circdir[c]:
				tstr = "arith.circ" # always prefer arith
			elif "bool_depth.circ" in circdir[c]:
				tstr = "bool_depth.circ" # then depth-optimized
			else:
				tstr = circdir[c][0] # use whatever we have (probably size-optimized)
			of.write(c+"@"+tstr+"\n")

	with open("yaohybrid.cmb", "w") as of:
		for c in circdir:
			if "arith.circ" in circdir[c]:
				tstr = "arith.circ" # always prefer arith
			elif "bool_size.circ" in circdir[c]:
				tstr = "bool_size.circ" # then size-optimized
			else:
				tstr = circdir[c][0] # use whatever we have (probably depth-optimized)
			of.write(c+"@"+tstr+"\n")


if __name__ == "__main__":
	main()
