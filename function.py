#The function of selective revocation scheme
from wrapper import BpGroup, G1Elem, G2Elem
from hashlib  import sha256
from binascii import hexlify, unhexlify
#from petlib.bn import Bn # only used to hash challange
import numpy as np

from bn128 import FQ

##############################
# Setup
##############################

def setup(q=1):
	# generate the system parameters
	assert q > 0
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	hs = [G.hashG1(("h%s" % i).encode("utf8")) for i in range(q)]
	e, o = G.pair, G.order()
	return (G, o, g1, hs, g2, e)
