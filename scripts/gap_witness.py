"""Same statement and enrolled predecessor for full and local G3 variants."""

from dataclasses import dataclass
import secrets

from circom_crypto import FIELD_P, OBUKeyPair, poseidon
from gap_model import GAP, endpoints, fixture, pins

PUBLIC = ("relation","sid","revision","policy","pkCommit","oldRoot","newRoot",
          "deposit","oldRefund","deltaRefund")


def blinding() -> int:
    return secrets.randbelow(FIELD_P)


@dataclass(frozen=True)
class CommittedGap:
    index: int
    mask: int
    observed: tuple
    upper: int
    salt: int

    def digest(self, sid: int) -> int:
        chain = poseidon([205200,sid,self.index,self.salt])
        for i,(a,b) in enumerate(self.observed):
            chain = poseidon([chain,(self.mask>>i)&1,a,b])
        return poseidon([205201,chain,self.upper])


def enroll_gap(index: int, path: tuple, mask: int) -> CommittedGap:
    return CommittedGap(index,mask,pins(path,mask),endpoints(path,mask,maximize=True),blinding())


def node(lhs: tuple[int,int], rhs: tuple[int,int]) -> tuple[int,int]:
    return poseidon([205202,*lhs,*rhs]), lhs[1]+rhs[1]


def tree(sid: int, leaves: tuple[CommittedGap,...]) -> list:
    level = [(leaf.digest(sid),leaf.upper) for leaf in leaves]
    output=[level]
    while len(level)>1:
        level=[node(lhs,rhs) for lhs,rhs in zip(level[::2],level[1::2],strict=True)]
        output.append(level)
    return output


class Pair:
    def __init__(self, n: int, sid: int=2053001) -> None:
        self.sid=sid
        self.routes=fixture(n)
        self.policy=205300+len(self.routes)
        self.key=OBUKeyPair(secrets.token_bytes(32))
        self.key_salt=blinding()
        self.group_index=len(self.routes)//2
        self.slot_index=1
        self.old=tuple(enroll_gap(i,route,0) for i,route in enumerate(self.routes))
        path=self.routes[self.group_index]
        self.a,self.b=path[self.slot_index:self.slot_index+2]
        updated=enroll_gap(self.group_index,path,1<<self.slot_index)
        self.new=self.old[:self.group_index]+(updated,)+self.old[self.group_index+1:]
        self.before=tree(sid,self.old)
        self.after=tree(sid,self.new)

    def input(self, local: bool) -> dict:
        root0, upper0 = self.before[-1][0]
        root1, upper1 = self.after[-1][0]
        leaves=(self.old[self.group_index],) if local else self.old
        signature=self.key.sign_field(poseidon([
            205203,self.sid,self.policy,4*self.group_index+self.slot_index,self.a,self.b,
        ]))
        data={
            "relation":205100+int(local),"sid":self.sid,"revision":0,"policy":self.policy,
            "pkCommit":self.key.pk_commit(self.key_salt),"oldRoot":root0,"newRoot":root1,
            "deposit":upper0,"oldRefund":0,"deltaRefund":upper0-upper1,
            "gapIndex":self.group_index,"slotIndex":self.slot_index,
            "Ax":self.key.Ax,"Ay":self.key.Ay,"pkSalt":self.key_salt,
            "R8x":signature.R8x,"R8y":signature.R8y,"S":signature.S,
            "oldSalt":[x.salt for x in leaves],"oldMask":[x.mask for x in leaves],
            "priorOrigin":[[a for a,_ in x.observed] for x in leaves],
            "priorTarget":[[b for _,b in x.observed] for x in leaves],
            "priorUpper":[x.upper for x in leaves],
            "newSalt":self.new[self.group_index].salt,
            "exactOrigin":self.a,"exactTarget":self.b,
        }
        if local and len(self.before)>1:
            siblings=[level[(self.group_index>>i)^1] for i,level in enumerate(self.before[:-1])]
            data["siblingHash"]=[h for h,_ in siblings]
            data["siblingUpper"]=[v for _,v in siblings]
        return data

CLOSE_PUBLIC = ("relation","sid","revision","policy","pkCommit","oldRoot","deposit",
                "oldRefund","infraMask","charge","refund","certifiedDigest")


class ClosePair:
    def __init__(self) -> None:
        self.routes=fixture(16)
        self.sid=2053301
        self.policy=205304
        self.rev=3
        self.key=OBUKeyPair(secrets.token_bytes(32))
        self.key_salt=blinding()
        self.cert_salt=blinding()
        self.mask=(0b1101,0b1011,0b0111,0b1111)
        self.fault=(1<<1)|(1<<6)
        self.infra=(1<<1)|(1<<11)
        self.leaves=tuple(enroll_gap(i,route,mask) for i,(route,mask)
                          in enumerate(zip(self.routes,self.mask,strict=True)))
        self.deposit=sum(endpoints(route,0,maximize=True) for route in self.routes)
        self.returned=11
        self.root,self.previous_upper=tree(self.sid,self.leaves)[-1][0]
        effective=self.fault & self.infra
        self.charge=sum(endpoints(route,mask,maximize=True,waived=(effective>>(4*i))&15)
                        for i,(route,mask) in enumerate(zip(self.routes,self.mask,strict=True)))
        assert self.charge<self.previous_upper

    def input(self, arm: int) -> dict:
        pk=self.key.pk_commit(self.key_salt)
        cert=poseidon([
            205208,self.sid,self.rev,self.policy,self.root,pk,self.deposit,
            self.returned,self.infra,self.charge,self.cert_salt,
        ])
        data={
            "relation":205210+arm,"sid":self.sid,"revision":self.rev,"policy":self.policy,
            "pkCommit":pk,"oldRoot":self.root,"deposit":self.deposit,"oldRefund":self.returned,
            "infraMask":self.infra,"charge":self.charge,"refund":self.deposit-self.returned-self.charge,
            "certifiedDigest":cert,"salt":self.cert_salt,
        }
        if arm:
            sig=self.key.sign_field(poseidon([205209,self.sid,self.rev,self.policy,self.fault]))
            data.update({
                "faultMask":[self.fault],"Ax":[self.key.Ax],"Ay":[self.key.Ay],
                "pkSalt":[self.key_salt],"R8x":[sig.R8x],"R8y":[sig.R8y],"S":[sig.S],
                "oldSalt":[x.salt for x in self.leaves],"oldMask":[x.mask for x in self.leaves],
                "priorOrigin":[[a for a,_ in x.observed] for x in self.leaves],
                "priorTarget":[[b for _,b in x.observed] for x in self.leaves],
                "priorUpper":[x.upper for x in self.leaves],
            })
        return data
