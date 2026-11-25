#!/usr/bin/env python3
"""Generate the manuscript facts, figures and tables from packaged receipts."""

import argparse
import json
from pathlib import Path
from statistics import median
from math import log2

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

ROOT = Path(__file__).resolve().parents[1]
COLORS = ("#475569", "#0072B2", "#009E73", "#D55E00")
ARMS = ("hold", "single_slot4_bucket", "multi_slot_bucket", "exact")
ARM_LABELS = ("Hold", "Slot 4 bucket", "Multi-slot bucket", "Exact")

plt.rcParams.update({"font.size": 8, "font.family": "serif", "axes.spines.top": False,
                     "axes.spines.right": False, "pdf.fonttype": 42})


def load(path):
    return json.loads(path.read_text())


def fmt(value, places=0):
    if value is None:
        return "--"
    return f"{value:,.{places}f}"


def pct(value, places=1):
    return fmt(value * 100, places) + r"\%"


def table(path, labels, records, caption, label, wide=False, extra=""):
    env = "table*" if wide else "table"
    cols = "l" + "r" * (len(labels)-1)
    lines = [
        rf"\begin{{{env}}}[t]", r"\centering", r"\scriptsize", r"\setlength{\tabcolsep}{4pt}",
        rf"\begin{{tabular}}{{@{{}}{cols}@{{}}}}", r"\toprule",
        " & ".join(labels) + r" \\", r"\midrule",
    ]
    for record in records:
        if record is None:
            lines.append(r"\midrule")
        else:
            lines.append(" & ".join(map(str, record)) + r" \\")
    lines.extend([r"\bottomrule", r"\end{tabular}", extra, rf"\caption{{{caption}}}",
                  rf"\label{{{label}}}", rf"\end{{{env}}}", ""])
    path.write_text("\n".join(lines))


def subplots():
    fig, axes = plt.subplots(1, 2, figsize=(7.0, 2.20))
    fig.subplots_adjust(left=.10, right=.98, wspace=.38, bottom=.27, top=.92)
    for label, axis in zip(("(a)", "(b)"), axes, strict=True):
        axis.grid(axis="y", alpha=.28)
        axis.set_axisbelow(True)
        axis.text(.5, -.35, label, transform=axis.transAxes, ha="center", va="top")
    return fig, axes


def finish(fig, path):
    fig.savefig(path, bbox_inches="tight", pad_inches=.06,
                metadata={"CreationDate": None, "ModDate": None, "Title": path.stem})
    plt.close(fig)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--artifact", type=Path, default=ROOT)
    parser.add_argument("--out", type=Path, required=True)
    args = parser.parse_args()
    directory = args.artifact / "receipts/v15_1"
    output = args.out
    figs, tables = output/"figures", output/"tables"
    figs.mkdir(parents=True,exist_ok=True)
    tables.mkdir(parents=True,exist_ok=True)

    builds = load(args.artifact/"compiled_circuits_manifest.json")["circuits"]
    proof_manifest = load(args.artifact/"proofs/manifest.json")
    setup = load(args.artifact/"phase2_setup_manifest.json")["relations"]
    release = load(args.artifact/"release_identity.json")
    rome = load(directory/"rome_proof_gated_replay.json")
    taiwan = load(directory/"m06a_proof_gated_replay.json")
    gap = load(directory/"gap_proof_gated_replay.json")
    gap_arms = load(directory/"gap_matched_close.json")["verified_arms"]
    models = load(directory/"rome_stopping.json")
    net = load(directory/"network.json")["curve"]
    synthetic = load(directory/"synthetic_lp.json")
    holdout = load(directory/"m06a_cohort.json")
    rome_cohort = load(directory/"rome_cohort_manifest.json")
    r_fleet = load(directory/"rome_release_fleet.json")
    t_fleet = load(directory/"m06a_release_fleet.json")
    host = load(directory/"host.json")
    under_load = load(directory/"host_concurrent_attempt.json")
    scale = load(directory/"historical_scaling.json")
    matched = load(directory/"matched_baselines.json")
    ext = {name: load(directory/"external_baselines"/f"{name}.json") for name in
           ("pretp", "erp", "fairstream", "cape", "fairrelay", "micronova")}
    contraction = load(directory/"historical_rome_contraction.json")
    old_checks = load(directory/"historical_exactness.json")

    t60 = next(row for row in net if row["seconds"] == 60)
    r120, t120 = (rec["fleet"]["single_slot4_bucket"] for rec in (r_fleet,t_fleet))
    facts = {
        "ReleaseIdentifier": release["identifier"],
        "ApplicationKeys": fmt(len(setup)),
        "PublicCoordinates": fmt(sum(len(builds[name]["public_input_names"]) for name in setup)),
        "CircuitMains": fmt(len(builds)),
        "CausalConstraints": fmt(builds["causal_update"]["constraints"]),
        "ProofBundles": fmt(len(proof_manifest)),
        "RomeProofs": fmt(rome["admissions"]),
        "TaiwanProofs": fmt(taiwan["admissions"]),
        "RomeSessions": fmt(rome["sessions"]),
        "TaiwanSessions": fmt(taiwan["sessions"]),
        "RomeTaxiHoldout": fmt(rome_cohort["splits"]["holdout"]["taxis"]),
        "RomeHoldoutCases": fmt(rome_cohort["splits"]["holdout"]["blocks"]),
        "RomeStopSites": fmt(models["matrix"]["causal"]["late"]["decisions"]),
        "RomeStopCausal": fmt(models["matrix"]["causal"]["strict_decisions"]),
        "RomeStopSealed": fmt(models["matrix"]["sealed"]["strict_decisions"]),
        "RomePriorGroups": fmt(r_fleet["privacy"]["hold"]["non_singleton_groups"]),
        "RomePriorBlocks": fmt(r_fleet["privacy"]["hold"]["non_singleton"]["records"]),
        "RomeSingleCapViolations": fmt(r_fleet["privacy"]["single_slot4_bucket"]["outcomes_exceeding_five_pp"]),
        "RomeMultiCapViolations": fmt(r_fleet["privacy"]["multi_slot_bucket"]["outcomes_exceeding_five_pp"]),
        "RomeExactCapViolations": fmt(r_fleet["privacy"]["exact"]["outcomes_exceeding_five_pp"]),
        "RomeBucketWidth": fmt(r_fleet["bucket_units"]),
        "TaiwanBucketWidth": fmt(t_fleet["bucket_units"]/10,1),
        "RomeSinglePeakSavings": pct(r120["peak_reduction_from_hold"]),
        "TaiwanSinglePeakSavings": pct(t120["peak_reduction_from_hold"]),
        "RomePeakConcurrent": fmt(r_fleet["fleet"]["hold"]["peak_open_sessions"]),
        "TaiwanPeakConcurrent": fmt(t_fleet["fleet"]["hold"]["peak_open_sessions"]),
        "TaiwanCalibration": fmt(holdout["calibration_trips"]),
        "TaiwanHoldout": fmt(holdout["selected_test_trips"]),
        "TaiwanListMatches": fmt(holdout["list_price_matches"]),
        "TaiwanAllowanceMatches": fmt(holdout["per_trip_allowance"]["matches"]),
        "TaiwanFleetRouteGroups": fmt(t_fleet["selected_case_privacy"]["hold"]["distinct_route_groups"]),
        "TaiwanGantries": fmt(holdout["gantries"]),
        "TaiwanEdges": fmt(holdout["directed_edges_including_exit"]),
        "NetworkTV": fmt(t60["empirical_tv"],5),
        "NetworkBound": fmt(t60["union_bound_on_true_tv"],4),
        "HostTrials": fmt(len(host["timings"])),
        "HostMedian": fmt(host["summary"]["total_ms"]["median"]/1000,3),
        "HostQone": fmt(host["summary"]["total_ms"]["q25"]/1000,3),
        "HostQthree": fmt(host["summary"]["total_ms"]["q75"]/1000,3),
        "HostPninetyfive": fmt(host["summary"]["total_ms"]["p95"]/1000,3),
        "HostRSS": fmt(host["peak_child_rss_mib"],1),
        "HostLoadedFailures": fmt(len(under_load["failures"])),
        "HostLoadedTrials": fmt(under_load["requested_measured_trials"]),
        "SyntheticSupport": fmt(synthetic["distinct_history_count"]),
        "SyntheticGain": pct(synthetic["liquidity_gain_relative"],0),
        "GapCloseMs": fmt(gap["digest_close_total_ms"],1),
        "GapCertifyCloseMs": fmt(gap["certify_and_close_total_ms"],1),
        "GapMatchedRawMs": fmt(gap_arms["gap_close_raw"]["prove_ms"],1),
        "GapMatchedStatefulMs": fmt(gap_arms["gap_close_stateful"]["prove_ms"],1),
        "GapMatchedDigestMs": fmt(gap_arms["gap_close_digest"]["prove_ms"],1),
        "HistoricalRomePrefix": fmt(old_checks["rome_prefixes_equal"]),
        "HistoricalSyntheticPrefix": fmt(old_checks["synthetic_prefixes_equal"]),
    }
    for kind in ("causal", "sealed"):
        for arm in ("late", "any"):
            facts["Stop"+kind.title()+arm.title()] = fmt(models["matrix"][kind][arm]["total_release_units"])
    translated = "".join(r"\newcommand{\%s}{%s}" % pair + "\n" for pair in sorted(facts.items()))
    (output/"facts.tex").write_text(translated)
    (output/"expected_facts.json").write_text(json.dumps(facts,indent=2,sort_keys=True)+"\n")

    # Figure 3. Historical component benchmark with explicit distribution boundaries.
    fig, (a,b) = subplots()
    v = sorted(scale["vertex_scaling_n8"].items(),key=lambda p:int(p[0]))
    x = np.arange(len(v))
    a.errorbar(x, [q["arm_A"]["median_ms"] for _,q in v],
               yerr=[q["arm_A"]["iqr_ms"]/2 for _,q in v], color=COLORS[1], marker="o", capsize=2)
    a.set_xticks(x, [n for n,_ in v])
    a.set_xlabel("Vertices")
    a.set_ylabel("Prover median (ms)")
    s = sorted(scale["slot_scaling_n24_full_vs_local"].items(),key=lambda p:int(p[0]))
    for index, (key, label) in enumerate((("arm_A","Full"), ("arm_B","Local")),1):
        b.plot([int(n) for n,_ in s], [row[key]["median_ms"] for _,row in s], "-o",
               label=label,color=COLORS[index])
    b.set_xlabel("Slots")
    b.set_ylabel("Prover median (ms)")
    b.legend()
    finish(fig, figs/"fig3_scaling.pdf")

    # Figure 4. Storage and close costs have separate measurement boundaries.
    fig, (a,b) = subplots()
    signed = matched["receipt"]
    catalogs = [signed[key]["pretrip_bytes"] for key in ("offline_factored","offline_coupled")]
    a.bar(("Factored", "Coupled"), np.array(catalogs)/1024, color=COLORS[1:3])
    a.set_yscale("log")
    a.set_ylabel("Offline catalog (KiB)")
    stages = [gap["certify_and_close_total_ms"]-gap["digest_close_total_ms"], gap["digest_close_total_ms"]]
    b.bar(("Certification","Digest close","Combined"), [*stages,sum(stages)], color=COLORS[1:])
    b.set_ylabel("Witness, prove, admit (ms)")
    finish(fig, figs/"fig6_baselines_close.pdf")

    # Figure 5. Finite-support policy and two-profile transport simulation.
    fig, (a,b) = subplots()
    policies = synthetic["heldout_markov_orders"]["2"]
    scope = ("hold","uniform_bucket","bayes_lp","exact")
    a.bar(("Hold","Uniform","Bayes-LP","Exact"), [policies[p]["utility_integral_mean"] for p in scope],
          color=COLORS)
    a.set_ylabel("Mean release integral")
    xx = np.arange(len(net))
    b.plot(xx,[q["empirical_tv"] for q in net],"-o",color=COLORS[1],label="Empirical TV")
    b.plot(xx,[q["union_bound_on_true_tv"] for q in net],"--s",color=COLORS[3],label="Tail bound")
    b.set_xticks(xx,[f"{row['seconds']} s" for row in net])
    b.set_ylabel("Total variation")
    b.set_xlabel("Buffer window")
    b.legend(fontsize=7)
    finish(fig, figs/"fig4_privacy_net.pdf")

    # Figure 6. Derive all four bars for each corridor from its own ledger receipt.
    fig, (a,b) = subplots()
    for row, color, label in zip(contraction, COLORS[1:3], ("Peak","Off-peak"),strict=True):
        upper = np.asarray(row["mean_upper_by_k"])/1000
        lower = np.asarray(row["mean_lower_by_k"])/1000
        a.plot(range(len(upper)),upper,color=color,label=label)
        a.fill_between(range(len(lower)),lower,upper,color=color,alpha=.12)
    a.set_xlabel("Recorded prefix")
    a.set_ylabel(r"Fee envelope ($10^3$ units)")
    a.legend()
    x = np.arange(2)
    for i, (arm, label, color) in enumerate(zip(ARMS, ARM_LABELS, COLORS, strict=True)):
        ratios = [100 * row["fleet"][arm]["peak_locked_escrow"] / row["fleet"]["hold"]["peak_locked_escrow"]
                  for row in (r_fleet, t_fleet)]
        b.bar(x + (i-1.5)*.19, ratios, .19,color=color,label=label)
    b.set_xticks(x, ("Rome", "Taiwan M06A"))
    b.set_ylabel("Peak escrow (% of Hold)")
    b.set_ylim(0, 145)
    b.set_yticks(range(0, 101, 20))
    b.legend(ncol=2,loc="upper center",fontsize=6.3)
    finish(fig, figs/"fig5_real_corridors.pdf")

    def proof_metrics(report, suffix):
        samples = [trial for trial in report["proofs"] if trial["relation"].endswith(suffix)]
        return [fmt(median(float(trial[k]) for trial in samples),p) for k,p in
                (("witness_ms",1),("prove_ms",1),("pairing_ms",2),("precommit_ms",2),
                 ("serialized_proof_public_bytes",0))]

    rows = [(f"Prepared $N={n}$",fmt(row["constraints"]),
              fmt(row["arm_A"]["median_ms"],1),fmt(row["arm_A"]["iqr_ms"],1),
              fmt(row["arm_A"]["p95_ms"],1),fmt(row["peak_rss_mb_A"],1)) for n,row in v]
    end = host["summary"]["total_ms"]
    rows += [None, ("Host end-to-end",fmt(builds["causal_update"]["constraints"]),fmt(end["median"],1),
                    fmt(end["q75"]-end["q25"],1),fmt(end["p95"],1),fmt(host["peak_child_rss_mib"],1))]
    table(tables/"tab_scaling_obu.tex", ("Configuration","R1CS","Med. ms","IQR","p95","MiB"), rows,
          "Historical prepared-witness scaling and paired host latency. The largest prepared circuit uses a different architecture. The host row includes witness, prove and verify.", "tab:scaling")

    basis = []
    for key,label in (
        ("plaintext","Plaintext evidence"), ("online_trusted","Online trusted source"),
        ("offline_factored",r"Factored offline $m\,2^g$"),
        ("offline_coupled",r"Coupled offline $2^n$"),
    ):
        row = signed[key]
        basis.append((label,fmt(row["catalog_rows"]),fmt(row["pretrip_bytes"]),fmt(row["pretrip_ms"],2),
                      fmt(row["update_wire_bytes"]),fmt(row["client_update_ms"],2),
                      fmt(row["charger_update_ms"],2),fmt(row["close_wire_bytes"]),
                      fmt(row["client_close_ms"],2)+" + "+fmt(row["charger_close_ms"],2)))
    basis.append(None)
    for label,report in (("TollVeil Taiwan",taiwan),("TollVeil Rome",rome)):
        witness, prove, verify, admit, wire = proof_metrics(report,"update")
        *_, close_wire = proof_metrics(report,"close")
        basis.append((label,"--","--","--",wire,witness+" + "+prove,admit,close_wire,"see Table~\\ref{tab:corridors}"))
    e = ext
    erp = e["erp"]
    size = erp["bytes_per_element"] * (erp["base_elements"] + erp["elements_per_round"] * int(log2(erp["value_bits"])))
    prim = (
        (r"PrETP~\cite{pretp2010}", "reimplemented eight-segment commitment and audit", fmt(e["pretp"]["complete_route_8slot_mean200_match"]["elapsed_ms_median"],2)+" ms"),
        (r"ERP~\cite{desmet2024} / Bulletproofs~\cite{bulletproofs2018}", "standalone 64-bit range-proof reference", fmt(size)+" B"),
        (r"FairStream~\cite{fairstream2023}", "pessimistic proof of misbehavior, modeled chain gas", fmt(e["fairstream"]["paper_reported_ethereum_gas"]["stream_PoM_gas"])+" gas"),
        (r"CAPE~\cite{cape2025}", "reimplemented private channel update proof", fmt(e["cape"]["circuit_benchmarks"]["C_Update"]["prove_s_median"],3)+" s"),
        (r"FairRelay~\cite{fairrelay2026}", "proof of forwarding circuit", fmt(e["fairrelay"]["pof128_groth16_benchmark"]["prove_s_median"],3)+" s"),
        (r"MicroNova~\cite{micronova2025}", "incremental fold and final compression", 
         fmt(median(e["micronova"]["step_prove_ms_median"]),1)+" / "+fmt(e["micronova"]["compressed_prove_at_k4_ms_median"],1)+" ms"),
    )
    appendix = (
        r"\par\smallskip\begin{tabular}{@{}llr@{}}\toprule"+"\n"+
        r"Related system & Measured operation and trust boundary & Reported cost \\"+"\n"+r"\midrule"+"\n"+
        "\n".join(" & ".join(v)+r" \\" for v in prim)+"\n"+r"\bottomrule\end{tabular}"
    )
    labels = ("Settlement arm","Rows","Store B","Prep ms","Upd B","Client ms","Admit ms","Close B","Close ms")
    table(tables/"tab_baselines.tex",labels,basis,
          "Authenticated settlement costs and related primitive references. The signed arms share a synthetic 16-slot task, and the TollVeil rows use the indicated corridor inputs. The offline catalogs assume route foreknowledge. Signed close reports client and charger medians separately.", "tab:baselines",True,appendix)

    rows = []
    for label, record in (("Rome",r_fleet),("Taiwan",t_fleet)):
        for arm, policy in zip(ARMS, ARM_LABELS, strict=True):
            p = record["privacy"][arm]
            z = p["all"]
            rows.append((label,policy,pct(z["expected_top1"]),fmt(z["min_entropy_leak_bits"],4),
                         pct(p["non_singleton"]["expected_top1"]),fmt(p["outcomes_exceeding_five_pp"])))
        if label == "Rome":
            rows.append(None)
    table(tables/"tab_privacy.tex",("Cohort","Amount view","Top-1","Bits","Group Top-1","$>5$ pp"),rows,
          "Second-order score after observing the complete intermediate amount vector. Group Top-1 uses non-singleton groups. Exact is an unconstrained reference.", "tab:privacy")

    rp,tp = (proof_metrics(r,"update") for r in (rome,taiwan))
    rc,tc = (proof_metrics(r,"close") for r in (rome,taiwan))
    table(tables/"tab_real_corridors.tex",("Metric","Rome","Taiwan"),[
        ("Selected proof sessions",facts["RomeSessions"],facts["TaiwanSessions"]),
        ("Admitted proofs",facts["RomeProofs"],facts["TaiwanProofs"]),
        ("Conservation errors",rome["conservation_errors"],taiwan["conservation_errors"]),
        ("Update witness / prove (ms)", " / ".join(rp[:2]), " / ".join(tp[:2])),
        ("Close witness / prove (ms)", " / ".join(rc[:2]), " / ".join(tc[:2])),
        ("Update pairing / precommit (ms)", " / ".join(rp[2:4]), " / ".join(tp[2:4])),
        ("Close pairing / precommit (ms)", " / ".join(rc[2:4]), " / ".join(tc[2:4])),
        ("Update / close bytes",rp[-1]+" / "+rc[-1],tp[-1]+" / "+tc[-1]),
        None,
        *((label+" escrow peak", *(fmt(row["fleet"][key]["peak_locked_escrow"]) for row in (r_fleet,t_fleet)))
          for key,label in zip(ARMS,ARM_LABELS,strict=True)),
    ],"Proof-gated replays on archived routes with synthetic credentials. Bytes count serialized proof and public vector. Precommit time includes pairing and transaction work before receipt insertion.","tab:corridors")
    print(f"Generated {len(facts)} facts, four figures and four tables")


if __name__ == "__main__":
    main()
