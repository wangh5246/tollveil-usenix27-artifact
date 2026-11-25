"""Two-time nonanticipative finite-support LP, reported as a sensitivity arm."""

from bisect import bisect_right
from collections import defaultdict
import json

import numpy as np
from scipy.optimize import linprog
from scipy.sparse import coo_matrix

from causal_profile import build
from phase2_compare import rome_records
from release_privacy import MarkovPrior, groups, route_terms, within_group_weights
from run_g4 import OUT, rome_histories, synthetic_routes

SLOTS=(4,7)
EPS=0.05


def fit(rows, weight, caps):
    values=sorted(set(caps))
    maps={}
    variable_count=0
    for start,end in values:
        possibilities=[(a,b) for a in range(start+1) for b in range(a,end+1)]
        maps[(start,end)]={x:variable_count+i for i,x in enumerate(possibilities)}
        variable_count+=len(possibilities)
    objective=np.zeros(variable_count)
    for v in caps:
        for (a,b),col in maps[v].items():
            objective[col]-=3*a+b

    eq: list[tuple[int,int,float]]=[]
    rhs=[]
    for map_ in maps.values():
        eq.extend((len(rhs),column,1) for column in map_.values())
        rhs.append(1)
    first={}
    for v, mapping in maps.items():
        start,end=v
        if start not in first:
            first[start]=v
            continue
        pair=first[start]
        for a in range(start+1):
            eq.extend((len(rhs),mapping[a,b],1) for b in range(a,end+1))
            eq.extend((len(rhs),maps[pair][a,b],-1) for b in range(a,pair[1]+1))
            rhs.append(0)

    rows_num=0
    inequalities=[]
    for idx in groups(rows).values():
        histories,prior=route_terms(rows,idx,weight)
        limit=min(1,prior+EPS)
        if limit==1:
            continue
        total=defaultdict(float)
        for i in idx:
            total[caps[i]]+=weight[i]
        outputs=set().union(*(maps[v] for v in total))
        for route in histories.values():
            route_prob=defaultdict(float)
            for i in route:
                route_prob[caps[i]]+=weight[i]
            for out in sorted(outputs):
                for v,mass in total.items():
                    if out in maps[v]:
                        inequalities.append((rows_num,maps[v][out],route_prob[v]-limit*mass))
                rows_num+=1

    def matrix(entries,n):
        rr,cc,v=zip(*entries) if entries else ([],[],[])
        return coo_matrix((v,(rr,cc)),shape=(n,variable_count)).tocsr()
    result=linprog(objective,A_ub=matrix(inequalities,rows_num),b_ub=np.zeros(rows_num),
        A_eq=matrix(eq,len(rhs)),b_eq=rhs,bounds=(0,1),method="highs",options={"threads":1})
    if not result.success:
        raise ValueError(result.message)
    policies={}
    for v,mapping in maps.items():
        table={output:float(result.x[col]) for output,col in mapping.items() if result.x[col]>1e-10}
        t=sum(table.values())
        policies[v]={output:prob/t for output,prob in table.items()}
    by_start=defaultdict(list)
    for a,b in values:
        by_start[a].append(b)
    starts=sorted(by_start)
    first_output={}
    for a,key in first.items():
        pool=defaultdict(float)
        for (x,_),prob in policies[key].items():
            pool[x]+=prob
        first_output[a]=dict(pool)
    for a,b in values:
        marginal=defaultdict(float)
        for (x,_),prob in policies[a,b].items():
            marginal[x]+=prob
        assert all(abs(marginal[x]-first_output[a].get(x,0))<1e-6
                   for x in marginal.keys()|first_output[a].keys())

    def policy(cap):
        # The first marginal is selected from the first observation only.
        a,b=cap
        at=bisect_right(starts,a)-1
        if at<0:
            return {(0,0):1.0}
        a=starts[at]
        second=by_start[a]
        bt=bisect_right(second,b)-1
        if bt<0:
            return {(x,x):p for x,p in first_output[a].items()}
        return policies[a,second[bt]]
    return policy,{"variables":variable_count,"pointwise_privacy_inequalities":rows_num,
                   "equalities_including_nonanticipation":len(rhs),"state_pairs":len(values)}


def score(rows,weight,caps,policy,units):
    amount=0
    top1=0.0
    prior_success=posterior_success=0.0
    worst=0.0
    violations=0
    for idx in groups(rows).values():
        counts,base=route_terms(rows,idx,weight)
        probabilities=defaultdict(lambda:defaultdict(float))
        freq=defaultdict(lambda:defaultdict(float))
        prior_success+=len(idx)*base
        for i in idx:
            for (a,b),q in policy(caps[i]).items():
                assert 0<=a<=b and a<=caps[i][0] and b<=caps[i][1]
                amount+=q*(3*a+b)*units
                probabilities[(a,b)][rows[i].route]+=q*weight[i]
                freq[(a,b)][rows[i].route]+=q
        for out,dist in probabilities.items():
            pmax=max(dist.values())
            excess=pmax/sum(dist.values())-base
            worst=max(worst,excess)
            violations+=int(excess>0.0500001)
            best=min(dist,key=lambda r:(-dist[r],r))
            top1+=freq[out][best]
            posterior_success+=len(idx)*pmax
    return {"liquidity_integral":amount/len(rows),"top1":top1/len(rows),
            "prior_vulnerability":prior_success/len(rows),
            "posterior_vulnerability":posterior_success/len(rows),
            "worst_pointwise_increase":float(worst),"budget_violations":violations}


def test(train,test,quantum):
    model=MarkovPrior(h.route for h in train)
    p,q=(within_group_weights(rows,model,2) for rows in (train,test))
    def states(rows):
        return [tuple(h.caps[k]//quantum for k in SLOTS) for h in rows]
    a,b=states(train),states(test)
    def bucket(width):
        return lambda cap:{(cap[0]//width*width,cap[1]//width*width):1.0}
    lp,detail=fit(train,p,a)
    candidates=[]
    for width in range(1,max(c[1] for c in a)+2):
        m=score(train,p,a,bucket(width),quantum)
        if m["budget_violations"]==0:
            candidates.append((m["liquidity_integral"],-width))
    opt_b=-max(candidates)[1]
    cal_lp=score(train,p,a,lp,quantum)
    assert cal_lp["budget_violations"]==0
    bh=score(test,q,b,bucket(opt_b),quantum)
    lh=score(test,q,b,lp,quantum)
    return {"train":len(train),"test":len(test),"calibration_lp":cal_lp,
            "calibration_uniform":score(train,p,a,bucket(opt_b),quantum),
            "heldout_lp":lh,"heldout_uniform":bh,"uniform_quantum":opt_b*quantum,
            "heldout_gain":lh["liquidity_integral"]/bh["liquidity_integral"]-1
                           if bh["liquidity_integral"]>0 else None,
            "unseen_combined_cap_states":sum(x not in set(a) for x in b),
            "solver":detail}


if __name__=="__main__":
    a,b,_=rome_records()
    profile=build()
    ret={"decision_slots":list(SLOTS),"rome_quantum":4000,
         "status":"diagnostic, distinct from the registered one-decision test"}
    ret["rome"]=test(rome_histories(a,profile,backward=True),rome_histories(b,profile,backward=True),4000)
    ret["synthetic"]=test(*synthetic_routes(),1)
    with (OUT/"causal_two_stage_lp_sensitivity.json").open("x") as handle:
        handle.write(json.dumps(ret,indent=2)+"\n")
    for arm in ("rome","synthetic"):
        d=ret[arm]
        print(arm,d["heldout_gain"],"violations",d["heldout_lp"]["budget_violations"],
              d["heldout_uniform"]["budget_violations"],flush=True)
