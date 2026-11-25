"""Check how much utility any safe release could add at each decision time."""

from collections import defaultdict
from pathlib import Path
import json
import numpy as np

from causal_profile import build
from phase2_compare import rome_records
from release_privacy import MarkovPrior, groups, route_terms, within_group_weights
from run_g4 import OUT, rome_histories

WIDTHS = (1000, 2000, 3000, 4000, 5000, 7500, 10000, 15000, 20000, 30000, 40000,
          60000, 80000, 120000, 160000)


def violation(data, weight, views) -> float:
    worst=0.0
    for idx in groups(data).values():
        terms,base=route_terms(data,idx,weight)
        if len(terms)==1:
            continue
        by_view=defaultdict(lambda:defaultdict(float))
        for i in idx:
            by_view[views[i]][data[i].route]+=weight[i]
        worst=max(worst,max(
            max(row.values())/sum(row.values())-base for row in by_view.values()
        ))
    return worst


def comparison(train,test):
    model=MarkovPrior(r.route for r in train)
    prior_train=within_group_weights(train,model,2)
    prior_test=within_group_weights(test,model,2)
    scenarios=[]
    for chosen in [(i,) for i in range(1,8)]+[tuple(range(1,8))]:
        rr=[]
        for lower,upper in zip(chosen,(*chosen[1:],8),strict=True):
            rr.append(upper-lower)
        def params(rows,width):
            return [tuple(h.caps[k]//width*width for k in chosen) for h in rows]
        def utility(views):
            return np.average([sum(a*b for a,b in zip(v,rr,strict=True)) for v in views])
        train_ranks=[]
        for width in WIDTHS:
            view=params(train,width)
            if violation(train,prior_train,view)<=0.05+1e-9:
                train_ranks.append((float(utility(view)),-width))
        if not train_ranks:
            continue
        pick=-max(train_ranks)[1]
        view=params(test,pick)
        u=float(utility(view))
        exact=float(utility([tuple(h.caps[k] for k in chosen) for h in test]))
        valid=bool(violation(test,prior_test,view)<=0.05+1e-9)
        # An oracle use of holdout chooses the best privacy-feasible
        # uniform policy from the declared sensitivity grid.
        diagnostics=[]
        for width in WIDTHS:
            test_view=params(test,width)
            if violation(test,prior_test,test_view)<=0.05+1e-9:
                diagnostics.append((float(utility(test_view)),-width))
        best,q=max(diagnostics)
        scenarios.append({
            "decision_slots":list(chosen),"widths_evaluated":list(WIDTHS),
            "calibration_selected_quantum":pick,"heldout_budget_met":valid,
            "heldout_bucket_integral":u,"heldout_safe_ceiling":exact,
            "max_gain_against_calibration_policy":exact/u-1 if u and valid else None,
            "holdout_oracle_quantum":-q,"holdout_oracle_bucket_integral":best,
            "max_gain_against_test_oracle_baseline":exact/best-1 if best else None,
        })
    return {"scope":"matched public schedule, release-only transcript, exact entry and terminal charge",
            "not_for_gate":True,"sensitivity_policies":scenarios}


if __name__=="__main__":
    p=build()
    cal,test,_=rome_records()
    contents=comparison(rome_histories(cal,p,backward=True),rome_histories(test,p,backward=True))
    f=OUT/"rome_utility_ceiling_r1.json"
    with f.open("x") as handle:
        handle.write(json.dumps(contents,indent=2)+"\n")
    for row in contents["sensitivity_policies"]:
        print(row["decision_slots"],row["calibration_selected_quantum"],row["heldout_budget_met"],
              row["max_gain_against_calibration_policy"],row["max_gain_against_test_oracle_baseline"])
