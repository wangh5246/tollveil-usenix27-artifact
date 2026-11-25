"""Exact finite-support release policies for the amount projection."""

from collections import defaultdict, deque
from dataclasses import dataclass
from math import exp
import numpy as np
from scipy.optimize import linprog
from scipy.sparse import coo_matrix
from scipy.sparse.csgraph import connected_components


@dataclass(frozen=True)
class History:
    route: tuple[int, ...]
    caps: tuple[int, ...]
    terminal: tuple[int, ...]
    prefix_information: tuple[tuple, ...] = ()
    settlement_context: tuple[int, ...] = ()

    @property
    def group(self) -> tuple:
        return self.settlement_context, self.route[0], self.terminal[-1]


class MarkovPrior:
    def __init__(self, routes, vertex_count: int = 396) -> None:
        from collections import Counter
        self.order1 = defaultdict(Counter)
        self.order2 = defaultdict(Counter)
        self.vertex_count = vertex_count
        for route in routes:
            for i, vertex in enumerate(route[1:], 1):
                self.order1[route[i-1]][vertex] += 1
                if i > 1:
                    self.order2[(route[i-2],route[i-1])][vertex] += 1

    def log_probability(self, route: tuple[int,...], order: int) -> float:
        from math import log
        score=0.0
        for i, v in enumerate(route[1:],1):
            prev = self.order1.get(route[i-1],{})
            p1=(prev.get(v,0)+0.25)/(sum(prev.values())+0.25*self.vertex_count)
            if order==2 and i>=2:
                nexts=self.order2.get((route[i-2],route[i-1]),{})
                score+=log((nexts.get(v,0)+4*p1)/(sum(nexts.values())+4))
            else:
                score+=log(p1)
        return score


def groups(rows: list[History]) -> dict:
    result=defaultdict(list)
    for i,h in enumerate(rows):
        result[h.group].append(i)
    return dict(result)


def within_group_weights(rows: list[History], model: MarkovPrior, order: int) -> np.ndarray:
    scored=np.array([model.log_probability(h.route,order) for h in rows])
    weight=np.zeros(len(rows))
    for idx in groups(rows).values():
        same=defaultdict(list)
        for i in idx:
            same[rows[i].route].append(i)
        norm=max(scored[i] for i in idx)
        for copies in same.values():
            for i in copies:
                weight[i]=exp(scored[i]-norm)/len(copies)
        weight[idx]/=weight[idx].sum()
    return weight


def zero_schedule(rows: list[History], mode: str, full: bool = True) -> list[list[int]]:
    """Contract equality and monotonicity cycles, then propagate on the DAG."""
    if mode not in {"late", "any"}:
        raise ValueError("Unknown stop policy")
    tmax=len(rows[0].caps)
    size=len(rows)*tmax
    parent=list(range(size))

    def find(i):
        while parent[i]!=i:
            parent[i]=parent[parent[i]]
            i=parent[i]
        return i

    def union(a,b):
        parent[find(a)]=find(b)

    bindings={}
    for j, row in enumerate(rows):
        for k in range(tmax):
            node=j*tmax+k
            stop_times=[tmax-1] if mode=="late" else range(k,tmax)
            keys=[("terminal",k,s,row.settlement_context,row.route[0],row.terminal[s]) for s in stop_times]
            if not full:
                observation = (row.prefix_information[k] if row.prefix_information
                               else (row.route[:max(1,k)],row.caps[:k+1]))
                keys.append(("prefix",k,row.settlement_context,row.route[0],observation))
            for label in keys:
                if label in bindings:
                    union(node,bindings[label])
                else:
                    bindings[label]=node
    cap={}
    reverse=defaultdict(set)
    for j,row in enumerate(rows):
        for k in range(tmax):
            group=find(j*tmax+k)
            cap[group]=min(row.caps[k],cap.get(group,row.caps[k]))
            if k:
                reverse[group].add(find(j*tmax+k-1))
    nodes = {root: j for j, root in enumerate(cap)}
    edges = [(nodes[parent], nodes[child]) for child in cap for parent in reverse[child]]
    starts, ends = zip(*edges) if edges else ([], [])
    adjacency = coo_matrix((np.ones(len(edges)), (starts, ends)), shape=(len(nodes), len(nodes))).tocsr()
    count, labels = connected_components(adjacency, directed=True, connection="strong")
    component = {root: int(labels[index]) for root, index in nodes.items()}
    component_caps = [max(cap.values())] * count
    for root, value in cap.items():
        index = component[root]
        component_caps[index] = min(component_caps[index], value)
    parents = [set() for _ in range(count)]
    children = [set() for _ in range(count)]
    for a, b in edges:
        u, v = int(labels[a]), int(labels[b])
        if u != v:
            parents[v].add(u)
            children[u].add(v)
    out_degree = list(map(len, children))
    queue = deque(j for j, degree in enumerate(out_degree) if degree == 0)
    while queue:
        node = queue.popleft()
        for prev in parents[node]:
            component_caps[prev] = min(component_caps[prev], component_caps[node])
            out_degree[prev] -= 1
            if out_degree[prev] == 0:
                queue.append(prev)
    return [[component_caps[component[find(j*tmax+k)]] for k in range(tmax)] for j in range(len(rows))]


def score_release_views(rows: list[History], weights, views: list[tuple]) -> dict:
    """Score the entire deterministic release vector in each terminal group."""
    if len(rows) != len(views) or len(rows) != len(weights) or not rows:
        raise ValueError("Release vectors and candidate histories must agree")
    numbers = {name: np.zeros(4) for name in ("all", "non_singleton")}
    violations = 0
    max_pointwise = 0.0
    group_count = 0
    distinct_routes_groups = 0
    distinct_routes_records = 0
    for idx in groups(rows).values():
        terms, prior = route_terms(rows, idx, weights)
        multi = len(idx) > 1
        group_count += int(multi)
        if len(terms) > 1:
            distinct_routes_groups += 1
            distinct_routes_records += len(idx)
        by_view = defaultdict(lambda: defaultdict(float))
        frequencies = defaultdict(lambda: defaultdict(int))
        for j in idx:
            by_view[views[j]][rows[j].route] += weights[j]
            frequencies[views[j]][rows[j].route] += 1
        vulnerability = correct = 0
        for symbol, probabilities in by_view.items():
            best_route = min(probabilities, key=lambda route: (-probabilities[route], route))
            top1 = probabilities[best_route]
            excess = top1 / sum(probabilities.values()) - prior
            violations += int(excess > 0.0500001)
            max_pointwise = max(max_pointwise, excess)
            vulnerability += top1
            correct += frequencies[symbol][best_route]
        stats = np.array([len(idx), len(idx)*prior, len(idx)*vulnerability, correct])
        numbers["all"] += stats
        if multi:
            numbers["non_singleton"] += stats
    output = {}
    for name, (count, prior, post, correct) in numbers.items():
        output[name] = {"records": int(count), "expected_top1": float(correct/count) if count else None,
                        "prior_vulnerability": float(prior/count) if count else None,
                        "posterior_vulnerability": float(post/count) if count else None,
                        "min_entropy_leak_bits": float(np.log2(post/prior)) if count else None}
    return {"groups": len(groups(rows)), "non_singleton_groups": group_count,
            "distinct_route_groups": distinct_routes_groups, "records_in_distinct_route_groups": distinct_routes_records,
            "worst_pointwise_increase": float(max_pointwise), "outcomes_exceeding_five_pp": violations, **output}


def route_terms(rows, idx, weights):
    terms=defaultdict(list)
    for i in idx:
        terms[rows[i].route].append(i)
    prior=max(sum(weights[i] for i in items) for items in terms.values())
    return terms,prior


def score(rows, weight, options, bounds, quantum, step, attack_weight=None):
    total=len(rows)
    utility=0.0
    predictions=np.zeros(3)
    grouped=groups(rows)
    multi_predictions=np.zeros(3)
    multi_count=0
    prior_total=0.0
    violation=0.0
    violations=0
    for idx in grouped.values():
        terms,prior=route_terms(rows,idx,weight)
        subset_count=len(idx)
        q_obs=defaultdict(lambda:defaultdict(float))
        predict_obs=defaultdict(lambda:defaultdict(float))
        real_obs=defaultdict(lambda:defaultdict(float))
        prior_total+=subset_count*prior
        for i in idx:
            for amount, probability in options(bounds[i]).items():
                if probability<=1e-10:
                    continue
                if not 0<=amount<=bounds[i]:
                    raise ValueError("unsafe release")
                utility+=amount*probability*quantum*(8-step)
                route=rows[i].route
                q_obs[amount][route]+=weight[i]*probability
                predict_obs[amount][route]+=(weight if attack_weight is None else attack_weight)[i]*probability
                real_obs[amount][route]+=probability
        is_multi=len(terms)>1
        if is_multi:
            multi_count+=subset_count
        for amount,route_mass in q_obs.items():
            excess=max(route_mass.values())/sum(route_mass.values())-prior
            violation=max(violation,excess)
            violations+=int(excess>0.0500001)
            ranked=sorted(predict_obs[amount],key=lambda route:(-predict_obs[amount][route],route))
            for resolution in (1,3):
                metric=sum(real_obs[amount][r] for r in ranked[:resolution])
                predictions[0 if resolution==1 else 1]+=metric
                if is_multi:
                    multi_predictions[0 if resolution==1 else 1]+=metric
            predictions[2]+=subset_count*max(route_mass.values())
    baseline=prior_total/total
    posterior=predictions[2]/total
    return {
        "utility_integral_mean":utility/total,
        "expected_top1":predictions[0]/total,"expected_top3":predictions[1]/total,
        "top1_nonsingleton":multi_predictions[0]/max(1,multi_count),
        "top3_nonsingleton":multi_predictions[1]/max(1,multi_count),
        "records_in_nonsingleton_class":multi_count,
        "posterior_vulnerability":posterior,"prior_vulnerability":baseline,
        "min_entropy_leak_bits":float(np.log2(posterior/baseline)),
        "worst_pointwise_increase":float(violation),
        "outcomes_exceeding_five_pp":violations,
    }


def optimize(rows, weights, caps: list[int]):
    eligible=sorted(set(caps))
    columns={}
    for v in eligible:
        for r in range(v+1):
            columns[(v,r)]=len(columns)
    objective=np.zeros(len(columns))
    for i,v in enumerate(caps):
        for r in range(v+1):
            objective[columns[(v,r)]]-=r
    eqr=[index for index,v in enumerate(eligible) for _ in range(v+1)]
    rows_idx=[]
    cols_idx=[]
    coefficients=[]
    constraint=0
    for indices in groups(rows).values():
        routes, prior=route_terms(rows,indices,weights)
        limit=min(prior+0.05,1)
        if limit==1:
            continue
        total=defaultdict(float)
        for i in indices:
            total[caps[i]]+=weights[i]
        for route in routes.values():
            partial=defaultdict(float)
            for i in route:
                partial[caps[i]]+=weights[i]
            for refund in range(max(total)+1):
                for v,mass in total.items():
                    if v>=refund:
                        rows_idx.append(constraint)
                        cols_idx.append(columns[(v,refund)])
                        coefficients.append(partial[v]-limit*mass)
                constraint+=1
    eq=coo_matrix((np.ones(len(columns)),(eqr,list(range(len(columns))))),
                  shape=(len(eligible),len(columns))).tocsr()
    inequality=coo_matrix((coefficients,(rows_idx,cols_idx)),shape=(constraint,len(columns))).tocsr()
    answer=linprog(objective,A_ub=inequality,b_ub=np.zeros(constraint),
                   A_eq=eq,b_eq=np.ones(len(eligible)),bounds=(0,1),method="highs",
                   options={"threads":1})
    if not answer.success:
        raise ValueError(answer.message)
    table={}
    for v in eligible:
        policy={r:float(answer.x[columns[v,r]]) for r in range(v+1) if answer.x[columns[v,r]]>1e-10}
        s=sum(policy.values())
        table[v]={r:p/s for r,p in policy.items()}
    def policy(cap):
        if cap in table:
            return table[cap]
        available=[v for v in eligible if v<=cap]
        return table[max(available)] if available else {0:1.0}
    return policy,{"variables":len(columns),"privacy_inequalities":constraint,"prior_supported_bins":len(table)}
