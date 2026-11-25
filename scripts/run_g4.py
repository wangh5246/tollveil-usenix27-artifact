"""Run the locked local finite-support privacy and liquidity comparisons."""

from collections import Counter
from itertools import product
import json
import math
from pathlib import Path
from random import Random

import numpy as np
from scipy.stats import beta

from causal_profile import LONG, SHORT, WORK, build
from causal_witness import Certifier
from phase2_compare import rome_records
from release_privacy import History, MarkovPrior, groups, optimize, score, within_group_weights, zero_schedule

OUT=WORK/"receipts/privacy_g4"
STEP=4
GRANULARITY=1000


def rome_histories(rows, profile, *, backward=False) -> list:
    ref=Certifier(profile)
    ix={c:i for i,c in enumerate(profile.cells)}
    registrations={}
    result=[]
    for raw, dist, _ in rows:
        path=tuple(ix[c] for c in raw)
        u=path[0]
        if u not in registrations:
            registrations[u]=ref.forward(u,(1,)*8,(LONG,)*8,{},0)
        deposit=registrations[u]
        max_now=[]
        pins={}
        observed=tuple(int(b not in profile.short[a])
                       for a,b in zip(path[:-1],path[1:],strict=True))
        for k in range(9):
            if k>=2:
                i=k-2
                pins[i]=path[i],path[i+1],dist[i]
            tiers=observed[:k]+(1,)*(8-k)
            caps=tuple(LONG if tier else SHORT for tier in tiers)
            upper = (ref.witness(u,tiers,caps,pins,0)["upper"] if backward
                     else ref.forward(u,tiers,caps,pins,0))
            max_now.append(upper)
        fee=sum(d*profile.rates[i][a] for i,(d,a) in enumerate(zip(dist,path[:-1],strict=True)))
        assert fee<=max_now[-1]
        observations = tuple(
            (path[:max(1,k)], tuple(dist[:max(0,k-1)]), observed[:k]) for k in range(9)
        )
        result.append(History(path,tuple(deposit-v for v in max_now),(*max_now[:-1],fee),observations))
    return result


def synthetic_routes() -> tuple[list,list]:
    # A first-step branch selects a public-width eight-slot fee tier;
    # indistinguishable fourth-step views differ in their remaining choices.
    out=[]
    for group,(lo,hi) in enumerate([(1,2),(3,5),(6,11),(11,16),(17,23),(22,29)]):
        entry=0
        charge=100-hi+group
        assert charge<=100-lo
        for tag,safe,fee in [(1,lo,charge),(1,lo,100-lo),(2,hi,charge)]:
            code=3*group+tag
            dest=100+len(out)
            path=(entry,code,code,code,code,code,dest,dest,dest)
            # Registered fees sum to Q on this path. The unresolved
            # branch's maximizing fee determines the safe release.
            cap=100-max(fee,100-safe)
            assert cap>=0
            out.append(History(path,(0,0,0,0,cap,cap,cap,cap,100-fee),
                               (100,100,100,100,100-cap,100-cap,100-cap,100-cap,fee)))
    return out*10,out*5


def policies(calibration, holdout, quantum):
    model=MarkovPrior(h.route for h in calibration)
    train_weights=within_group_weights(calibration,model,2)
    test_weights={order:within_group_weights(holdout,model,order) for order in (1,2)}
    train_caps=[h.caps[STEP]//quantum for h in calibration]
    test_caps=[h.caps[STEP]//quantum for h in holdout]
    lp,details=optimize(calibration,train_weights,train_caps)
    def bucket(step):
        def release(cap):
            return {cap//step*step:1.0}
        return release
    candidates=[]
    for width in range(1,max(train_caps)+2):
        f=bucket(width)
        x=score(calibration,train_weights,f,train_caps,quantum,STEP)
        if x["outcomes_exceeding_five_pp"]==0:
            candidates.append((x["utility_integral_mean"],width))
    _,width=max(candidates,key=lambda item:(item[0],-item[1]))
    arms={"exact":bucket(1),"uniform_bucket":bucket(width),"bayes_lp":lp,"hold":lambda v:{0:1.0}}
    fit_scores={name:score(calibration,train_weights,fn,train_caps,quantum,STEP)
                for name,fn in arms.items()}
    assert fit_scores["bayes_lp"]["outcomes_exceeding_five_pp"]==0
    metrics={}
    for order,weight in test_weights.items():
        metrics[str(order)]={name:score(holdout,weight,fn,test_caps,quantum,STEP)
                             for name,fn in arms.items()}
        exact_caps=[h.caps[STEP] for h in holdout]
        metrics[str(order)]["exact"]=score(holdout,weight,bucket(1),exact_caps,1,STEP)
    second=metrics["2"]
    ub=second["uniform_bucket"]["utility_integral_mean"]
    opt=second["bayes_lp"]["utility_integral_mean"]
    optimistic, ceiling=optimize(holdout,test_weights[2],test_caps)
    refit_metrics=score(holdout,test_weights[2],optimistic,test_caps,quantum,STEP)
    eligible_heldout_buckets=[]
    for width_test in range(1,max(test_caps)+2):
        item=score(holdout,test_weights[2],bucket(width_test),test_caps,quantum,STEP)
        if item["outcomes_exceeding_five_pp"]==0:
            eligible_heldout_buckets.append((item["utility_integral_mean"],width_test))
    best_heldout=max(eligible_heldout_buckets)
    pointwise=all(second[k]["outcomes_exceeding_five_pp"]==0 for k in ("uniform_bucket","bayes_lp"))
    return {
        "calibration_rows":len(calibration),"heldout_rows":len(holdout),
        "terminal_group_counts":dict(Counter(map(len,groups(holdout).values()))),
        "policy_grid_amount":quantum,"decision_slot":STEP,
        "uniform_bucket_units":quantum*width,"fit":fit_scores,"heldout_markov_orders":metrics,
        "liquidity_gain_relative":opt/ub-1 if ub>0 else None,
        "lp_pointwise_constraints_met_on_holdout":pointwise,"lp_fit":details,
        "unseen_cap_rows":sum(c not in train_caps for c in test_caps),
        "test_refit_diagnostic":refit_metrics|ceiling|{
            "strongest_eligible_test_refit_bucket_utility":best_heldout[0],
            "strongest_eligible_test_refit_bucket_size":best_heldout[1]*quantum,
        },
    }


def stopping(rows):
    sealed=zero_schedule(rows,"late")
    causal=zero_schedule(rows,"late",full=False)
    exp=zero_schedule(rows,"any")
    assert all(len(x)==len(h.caps) for x,h in zip(sealed,rows))
    assert all(0<=w<=l<=cap for h,e,s in zip(rows,exp,sealed)
               for w,l,cap in zip(e,s,h.caps))
    assert all(0<=w<=l for c,s in zip(causal,sealed) for w,l in zip(c,s))
    assert all(a<=b for arm in (sealed,causal,exp) for amounts in arm
               for a,b in zip(amounts,amounts[1:]))
    shrink=[sum(a>b for a,b in zip(s,e)) for s,e in zip(sealed,exp)]
    return {"comparisons":sum(map(len,sealed)),"rows":len(rows),
            "exogenous_strict_components_cases":sum(k>0 for k in shrink),
            "strict_decisions":sum(shrink),
            "causal_late_strict_compared_to_sealed":sum(a>b for s,c in zip(sealed,causal)
                                                      for a,b in zip(s,c))}


def validate_stopping():
    rows=[
        History((0,1), (0,0,0), (3,3,0)),
        History((0,2), (0,0,0), (3,3,3)),
        History((0,3), (0,1,1), (2,2,0)),
        History((0,4), (0,1,1), (2,2,2)),
    ]
    def exhaustive():
        for mode in ("late","any"):
            optimum=zero_schedule(rows,mode)
            t=3
            upper=[0]*(t*len(rows))
            for all_caps in product(*(range(c+1) for h in rows for c in h.caps)):
                if any(all_caps[j*t+k]>all_caps[j*t+k+1] for j in range(4) for k in range(t-1)):
                    continue
                keys={}
                is_valid=True
                for j,h in enumerate(rows):
                    for k in range(t):
                        for s in ([t-1] if mode=="late" else range(k,t)):
                            key=k,s,h.terminal[s]
                            v=all_caps[j*t+k]
                            if key in keys and keys[key]!=v:
                                is_valid=False
                            keys[key]=v
                if is_valid:
                    upper=list(map(max,upper,all_caps))
            assert upper==[v for row in optimum for v in row]
    exhaustive()
    assert stopping(rows)["strict_decisions"]>0
    return {"small_domain_exhaustive_greatest_schedule_check":True}


def network(seed=20261124,samples=50000):
    rng=np.random.default_rng(seed)
    profiles=((0.02,12,0.60),(0.12,26,0.60))
    path_delays=[]
    for outage_p,median,sigma in profiles:
        jitter=np.minimum(0.5,rng.lognormal(np.log(0.045),0.55,(samples,8)))
        burst=rng.random(samples)<outage_p
        start=rng.integers(0,8,size=samples)
        duration=rng.lognormal(np.log(median),sigma,samples)*burst
        elapsed=(np.arange(8)[None,:]-start[:,None])*5.0
        residual=np.where(elapsed>=0,np.maximum(duration[:,None]-elapsed,0),0)
        path_delays.append(jitter+residual)
    curve=[]
    for window in (0,15,60,300):
        distributions=[]
        tails=[]
        for arr in path_delays:
            residual=np.maximum(0,arr-window)
            view=np.digitize(residual,[0.00001,0.1,0.5,1.,5.,15.,30.,60.])
            distributions.append(Counter(map(tuple,view)))
            k=int(np.count_nonzero(np.any(arr>window,axis=1)))
            tails.append({
                "late_sessions":k,"n":samples,"probability":k/samples,
                "upper95_bonferroni":float(beta.ppf(1-0.05/8,k+1,samples-k)) if k<samples else 1.0,
            })
        p,q=distributions
        tv=sum(abs(p[key]-q[key]) for key in p.keys()|q.keys())/(2*samples)
        curve.append({"seconds":window,"empirical_tv":tv,
                      "union_bound_on_true_tv":min(1,sum(x["upper95_bonferroni"] for x in tails)),
                      "tails":tails,"distinct_views":[len(p),len(q)]})
    return {"model":"two simulated routes, shared reconnect burst and per-message jitter",
            "samples_per_route":samples,"seed":seed,"traffic_spacing_seconds":5,
            "reconnect_cases":[{"burst_probability":p,"median_seconds":m,"log_sigma":s} for p,m,s in profiles],
            "jitter":"lognormal median 45 ms, log sigma .55, clipped at .5 seconds",
            "3gpp_context":"TR 37.885, V2X system evaluation methodology; reduced-order delay model is not 3GPP conformance",
            "fixed_release_schedule_assumed":True,"physical_route_measurement":False,"curve":curve}


def persist(path, value):
    with path.open("x") as f:
        f.write(json.dumps(value,indent=2)+"\n")


if __name__=="__main__":
    profile=build()
    a,b,split=rome_records()
    cal,test=rome_histories(a,profile),rome_histories(b,profile)
    s,t=synthetic_routes()
    persist(OUT/"network.json",network())
    persist(OUT/"stopping.json",validate_stopping()|{"rome":stopping(test),"synthetic":stopping(t)})
    persist(OUT/"synthetic_lp.json",policies(s,t,1))
    persist(OUT/"rome_lp.json",split|policies(cal,test,GRANULARITY))
    print("G4 models and measurements recorded",flush=True)
