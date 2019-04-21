""" tests """

from ethereum_selective import setup,CAKeygen,request,blind,unblind,show_credential,verify_credential,revoke_credential,thaw,revaction
from ethereum_selective import inv,to_challenge,prove_commitment,verify_commitment,sign,randomize,prove_show_credential

from bn128 import FQ, pairing


# ==================================================
# test
# ==================================================

def test_selective():
	params=setup()
	(sk,vk,delta,k,alpha)=CAKeygen(params)
	(S1, S2, proof, z)=request(params,alpha,vk)
	(sigg,W1,k1)=blind(params,sk,S1,S2,vk,proof,delta,k)
	C=unblind(params,vk,sigg,W1,k1,z,alpha)
	(bate, sig, W1, k1)=C
	(c, d, E, F, proof)=show_credential(params,vk,C,delta)
	#(c, d, E, F, delta, proof)=show_credential_revocation(params,vk,C,delta,k,sk)
	#verify
	assert verify_credential(params,vk,c,d,E,F,proof,delta)
	(delta, k2)=revoke_credential(params,vk,sk,delta,k)
	(gamal,L,Wk3,k3)=thaw(params,vk,c,d,S2,bate,delta,k,sk)
	revaction(params,L,k,vk,S2)
