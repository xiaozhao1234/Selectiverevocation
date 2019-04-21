from wrapper import BpGroup, G1Elem, G2Elem
from hashlib  import sha256
from binascii import hexlify, unhexlify
#from petlib.bn import Bn # only used to hash challange
import numpy as np

from bn128 import FQ


# ==================================================
# setup
# ==================================================

def setup(q=1):
	assert q > 0
	G = BpGroup()
	g1, g2 = G.gen1(), G.gen2()
	e, o = G.pair, G.order()
	return (G, o, g1, g2, e)


# ==================================================
# CAKeygen
# ==================================================

def CAKeygen(params):
    """ generate a key pair of CA """
    (G, o, g1, g2, e) = params
    #n=2
    (x, y) = o.random(), o.random()
    sk = (x, y)
    vk = (g2, y*g1, x*g2, y*g2)
    (k1, k2, k3, k4) = o.random(), o.random(), o.random(), o.random()
    k = (k1, k2, k3, k4)
    yn = ((y+k1)%o)*((y+k2)%o)*((y+k3)%o)*((y+k4)%o)%o
    h=o.random()
    g3=h*g1
    delta = yn*g3
    alpha=o.random()
    return (sk, vk, delta, k, alpha)

# ===================================================
# inversion
# ===================================================
def inv(a, n):  ### EDITED ###
	""" extended euclidean algorithm """
	if a == 0:
		return 0
	lm, hm = 1, 0
	low, high = a % n, n
	while low > 1:
		r = high//low
		nm, new = hm-lm*r, high-low*r
		lm, low, hm, high = nm, new, lm, low
	return lm % n
# ====================================================
# generate to_challenge
# ====================================================
def to_challenge(elements):
    """ generates a Bn challenge by hashing a number of EC points """
    Cstring = b",".join([hexlify(x.export()) for x in elements])
    Chash =  sha256(Cstring).digest()
    #return Bn.from_binary(Chash)
    return int.from_bytes(Chash, 'big') ### EDITED ###

# ===================================================
# issue
# ===================================================
    """signature on hidden message"""
# ===================================================
# request
# ===================================================

def request(params, alpha, vk):
	""" build elements for blind sign """
	(G, o, g1, g2, e) = params
	(g2, Y1, X2, Y2) = vk
	# build commitment
	z = o.random()
	#alpha = o.random()
	S1 = z*g1 + alpha*Y1
	S2 = alpha*Y2
	# proof of correctness
	proof = prove_commitment(params, vk, S1, S2, z, alpha)
	return (S1, S2, proof, z)

def prove_commitment(params, vk, S1, S2, z, alpha,q=1):
    """ prove correct commitment """
    (G, o, g1, g2, e) = params
    (g2, Y1, X2, Y2) = vk
    # create the proof
    u1, u2 = o.random(), o.random()
    # compute the witnesses commitments
    a = u1 * g1+ u2*Y1
    b = u2*Y2
    # create the challenge

    #c = to_challenge([g1, g2,(o.random())*g2, (o.random())*g2,Aw]+[g1])
    c = to_challenge([g1, g2, S1, S2, a, b]+[g1])
    # create responses
    s1 = (u1 + c * z) % o
    s2 = (u2 + c * alpha) % o

    return (c, s1, s2, a, b)

# ===============================================
# Blind_signature
# ===============================================

def blind(params, sk, S1, S2, vk, proof, delta, k):
	""" blindly sign a message """
	(G, o, g1, g2, e) = params
	(x, y) = sk
	(g2, Y1, X2, Y2) = vk
	(k1, k2, k3, k4) = k
	# verify proof of correctness
	if not verify_commitment(params, vk, S1, S2, proof):
		raise Exception('Parameters format error.')
	# issue PS signature
	Z = S1+k1*Y1
	u = o.random()
	A = u*g1
	B = u*(x*g1+Z)
	sigg =(A, B)
	# Witness for user 1
	W1 = (inv(y+k1, o))*delta
	return (sigg, W1, k1)

def verify_commitment(params, vk, S1, S2, proof):
	""" verify correct commitment """
	(G, o, g1, g2, e) = params
	(g2, Y1, X2, Y2) = vk
	(c, s1, s2, a, b) = proof

	# re-compute witnesses commitments
	verify1 = s1*g1+s2*Y1
	verify2 = s2*Y2
	assert verify1 == a+c*S1
	assert verify2 == b+c*S2
	# compute the challenge prime
	return (c == to_challenge([g1, g2, S1, S2, a, b]+[g1]))
# ======================================================
# PS signatures
# ======================================================
def sign(params, sk, m):
	""" sign a clear message """
	(G, o, g1, hs, g2, e) = params
	(x, y) = sk
	uu = o.random()
	A = uu*g1
	B = uu*((x+y*m)*g1)
	sig = (A, B)
	return (sig)
# =======================================================
# Randomize
# =======================================================
def randomize(params, sigg):
	""" randomize signature  """
	(G, o, g1, g2, e) = params
	sig1 , sig2 = sigg
	t = o.random()
	return ( t*sig1 , t*sig2 )

# ======================================================
# Unblind
# ======================================================
def unblind(params, vk, sigg, W1, k1, z, alpha):
	""" unblind the credential """
	(G, o, g1, g2, e) = params
	(g2, Y1, X2, Y2) = vk
	(sig1, sig2) = sigg
	bate = (alpha+k1)%o
	B1 =sig2-(z*sig1)
	sig = (sig1,B1)
	C= (bate, sig, W1, k1)
	return (C)


# ======================================================
# Showing
# ======================================================

#without the revocation element
def show_credential(params, vk, C, delta):
    (G, o, g1, g2, e) = params
    (g2, Y1, X2, Y2) = vk
    (bate, sig, W1, k1) = C
	#randomize ps signatures
    D = randomize(params, sig)
    (c, d) = D
    #commitment
    r = o.random()
    E = X2 + bate*Y2 + r*g2
    F = r*c
	# generate proof
    proof = prove_show_credential(params, vk, c, d, r, E, F, delta, bate, W1, k1)
    return (c, d, E, F, proof)

    #"""with the revocation element k2"""
#def show_credential_revocation(params, vk, C, delta, k, sk):
#	""" build elements for verify """
#	(G, o, g1, g2, e) = params
##	(bate, sig, W1, k1) = C
#	(k11, k2, k3, k4) = k
#	(x, y)=sk
#	assert k1 == k11
	#randomize ps signatures
#	D = randomize(params, sig)
#	(c, d) = D
#	r = o.random()
	#commitment
#	E = X2+(bate*Y2)+(r*g2)
#	F = r*c
	# The element k2 is revoked
	# replace k2 with a other letter
#	kr=(k2-k1)%o
    # The element k2 is revoked
#	k2 = (y+k2)%o
#	deltanew = (inv(k2, o))*delta
	#update delta
#	delta1 = deltanew
	#update witness
#	f=W1-delta1
#	W11=(inv(kr,o))*f
#	W1=W11
    # generate proof
#	proof = prove_show_credential(params, vk, c, d, r, E, F, delta1, bate, W1, k1)
#	return (c, d, E, F, delta1, proof)


# ==============================================================
# zero-knowledge proof of credential
# ==============================================================
def prove_show_credential(params, vk, c, d, r, E, F, delta, bate, W1, k1):
    """ prove correct commitment """
    (G, o, g1, g2, e) = params
    (g2, Y1, X2, Y2) = vk
	# Transfer
	# The prover generate the proof# create the witnesses
    rw = o.random()
    a = rw*Y2
    b = W1+rw*g1
    kappa = (rw*k1)%o
	#qq compute value
	#qq=e(g1,a)*e(g1,kappa*g2)*e(b,(inv(k1,o))*g2)
    # proof the knowledge bate,r,rw,kappa,k1
    # The prover generate the proof
    # create commitment
    (rho1, rho2, rho3, rho4, rho5) = o.random(), o.random(), o.random(), o.random(), o.random()
	#rho=(rho1, rho2, rho3, rho4, rho5)
    #compute the commitment
    v = X2+rho1*Y2+rho2*g2
    f = rho2*c
    a1 = rho3*Y2
    b1 = e(g1,a)*e(g1,rho4*g2)*e(b,rho5*g2)

    # create the challeng
	#c1 = to_challenge([g1, g2]+[g1])
    c1 = to_challenge([g1, g2, v, f]+[g1])
	#c1 = to_challenge()
    #c = to_challenge([g1, g2, v, f, a1, b1]+[g1])
    # create responses
    s1 = (rho1 + c1 * bate) % o
    s2 = (rho2 + c1 * r) % o
    s3 = (rho3 + c1 * rw) % o
    s4 = (rho4 + c1 * kappa) % o
    s5 = (rho5 + c1 * k1) % o
    return (c1, s1, s2, s3, s4, s5, v, f, a1, b1, a, b, kappa, k1)

# =======================================================
# Verify
# =======================================================

def verify_credential(params, vk, c, d, E, F, proof, delta):
    #""" verify a credential on a hidden message """
	(G, o, g1, g2, e) = params
	(g2, Y1, X2, Y2) = vk
	(c1, s1, s2, s3, s4, s5, v, f, a1, b1, a, b, kappa, k1) = proof
	#(rho1, rho2, rho3, rho4, rho5)=rho
	assert X2+(s1*Y2)+(s2*g2) == v+(c1*E)-(c1*X2)
	assert s2*c == f+c1*F
	assert s3*Y2 == a1+c1*a
	# left
	#left of pairing
	f1=e(g1, a)
	f2=e(g1, s4*g2)
	f3=e(b, s5*g2)
	f4=e(g1, c1*a)
	f5=f1*f2*f3*f4
	#right
	#right of pairing
	qq=e(g1,c1*a)
	qq1=e(g1, ((c1*kappa)%o)*g2)
	qq2=e(b,((c1*k1)%o)*g2)
	r3 =qq2*qq*qq1*b1
	assert f5 == r3
	#if e(c,E) == e(d+F, g2):
	#	print ('true')
	#else:
	#	print ('false')
	assert e(c,E) == e(d+F, g2)
	return (c1 == to_challenge([g1, g2, v, f]+[g1]))

# =======================================================
# Suspension
# =======================================================

def revoke_credential(params, vk, sk, delta, k):
	"""with the revocation element k2"""
	(G, o, g1, g2, e) = params
	(g2, Y1, X2, Y2) = vk
	(k1, k2, k3, k4) = k
	(x, y)=sk
	# The element k2 is revoked
	k2 = (y+k2)%o
	deltanew = (inv(k2, o))*delta
    #update delta
	delta = deltanew
    #update witness
	#k21 = (k2-k1)%o
	#W11=(inv(k21, o))*(W1-delta)
	#W1=W11
	#k31 = (k2-k3)%o
	#W31=(inv(k21, o))*(W1-delta)
	#W1=W11
	#k21 = (k2-k1)%o
	#W11=(inv(k21, o))*(W1-delta)
	#W1=W11
	return (delta, k2)

# =======================================================
# Thaw
# =======================================================
def thaw(params,vk,c,d,S2,bate,delta,k,sk):
    (G, o, g1, g2, e) = params
    (g2, Y1, X2, Y2) = vk
    (k1, k2, k3, k4) = k
    (x,y)=sk
    """user 1 sends request to CA with vlaue c and S1"""
    S1= bate*G.hashG1(c.export())
    #CA verifies assert
    assert e(S1,Y2)==e(G.hashG1(c.export()),S2+k1*Y2)
    #selet k3 to compute witnesses
    V = y*c
    Wk3 = (inv(y+k3, o))*delta
    #send values(V,Wk3,k3) to user1
    #update
    r=d+(k3-k1)*V
    sign=(c,r)
    L=randomize(params,sign)
    gamal=(bate+k3-k1)%o
    return (gamal,L,Wk3,k3)
# =======================================================
# revocation
# =======================================================
def revaction(params,L,k,vk,S2):
    #CA pubish k3 and s2 to blockchain to revoke the user1
	(G, o, g1, g2, e) = params
	(K, R)=L
	(g2, Y1, X2, Y2) = vk
	(k1, k2, k3, k4) = k
	wq=e(R,g2)
	we=e(K,X2)*e(K,S2+k3*Y2)
	assert (wq==we)
