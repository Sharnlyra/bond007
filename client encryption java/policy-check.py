#!/usr/bin/env python3
"""
Crypto Finder Policy Checker
Enforce cryptographic policies against scan results.
Exit code 0 = all clear, exit code 1 = policy violations found.
"""

import json
import os
import sys

from rich import box
from rich.console import Console
from rich.panel import Panel
from rich.rule import Rule
from rich.table import Table
from rich.text import Text

console = Console()


def load_json(path):
    with open(path) as f:
        return json.load(f)


def check_policy(results, policy):
    """Check results against policy. Returns (violations, warnings)."""
    violations = []
    warnings = []

    deny = policy.get("deny", {})
    warn = policy.get("warn", {})

    deny_algorithms = [a.lower() for a in deny.get("algorithms", [])]
    deny_families = [f.lower() for f in deny.get("algorithm_families", [])]
    deny_primitives = [p.lower() for p in deny.get("primitives", [])]

    warn_algorithms = [a.lower() for a in warn.get("algorithms", [])]
    warn_families = [f.lower() for f in warn.get("algorithm_families", [])]
    warn_primitives = [p.lower() for p in warn.get("primitives", [])]
    warn_notes = warn.get("notes", {})

    for finding in results.get("findings", []):
        file_path = finding["file_path"]
        for asset in finding["cryptographic_assets"]:
            meta = asset.get("metadata", {})
            asset_type = meta.get("assetType", "")

            algo_name = (meta.get("algorithmName") or "").lower()
            algo_family = (meta.get("algorithmFamily") or "").lower()
            primitive = (meta.get("algorithmPrimitive") or "").lower()
            material_type = (meta.get("materialType") or "").lower()

            # Display name for reporting
            display_name = (
                meta.get("algorithmName")
                or meta.get("algorithmFamily")
                or meta.get("materialType")
                or meta.get("certificateType")
                or "unknown"
            )

            location = f"{file_path}:{asset['start_line']}"

            # Check DENY rules
            denied = False
            deny_reason = ""

            if algo_name in deny_algorithms:
                denied = True
                deny_reason = f"Algorithm '{display_name}' is blocked by policy"
            elif algo_family in deny_families:
                denied = True
                deny_reason = f"Algorithm family '{meta.get('algorithmFamily', '')}' is blocked by policy"
            elif primitive in deny_primitives:
                denied = True
                deny_reason = f"Primitive '{primitive}' is blocked by policy"

            if denied:
                violations.append(
                    {
                        "location": location,
                        "asset": display_name,
                        "type": asset_type,
                        "reason": deny_reason,
                        "match": asset.get("match", ""),
                        "primitive": primitive,
                    }
                )
                continue

            # Check WARN rules
            warned = False
            warn_reason = ""
            note = ""

            if algo_name in warn_algorithms:
                warned = True
                warn_reason = f"Algorithm '{display_name}' flagged for review"
                note = warn_notes.get(meta.get("algorithmName", ""), "")
            elif algo_family in warn_families:
                warned = True
                warn_reason = f"Algorithm family '{meta.get('algorithmFamily', '')}' flagged for review"
                note = warn_notes.get(meta.get("algorithmFamily", ""), "")
            elif primitive in warn_primitives:
                warned = True
                warn_reason = f"Primitive '{primitive}' flagged for review"

            if warned:
                warnings.append(
                    {
                        "location": location,
                        "asset": display_name,
                        "type": asset_type,
                        "reason": warn_reason,
                        "note": note,
                        "match": asset.get("match", ""),
                    }
                )

    return violations, warnings


def display_results(policy, violations, warnings, total_assets):
    """Display policy check results."""
    console.print()

    # Policy header
    policy_name = policy.get("name", "Unnamed Policy")
    policy_desc = policy.get("description", "")
    header = Text()
    header.append("  POLICY CHECK  ", style="bold white on blue")
    header.append(f"  {policy_name}", style="bold blue")
    console.print(Panel(header, border_style="blue", box=box.DOUBLE))

    if policy_desc:
        console.print(f"  [dim]{policy_desc}[/]")
    console.print()

    # Summary
    passed = total_assets - len(violations) - len(warnings)

    summary_parts = []
    summary_parts.append(f"[green]\u2713 {passed} passed[/]")
    if warnings:
        summary_parts.append(f"[yellow]\u26a0 {len(warnings)} warnings[/]")
    if violations:
        summary_parts.append(f"[red]\u2717 {len(violations)} violations[/]")

    summary_str = " \u2022 ".join(summary_parts)
    console.print(f"  {summary_str}  [dim]({total_assets} total assets)[/]")
    console.print()

    # Violations table
    if violations:
        console.print(Rule("[bold red]VIOLATIONS (build will fail)[/]", style="red"))
        console.print()

        v_table = Table(
            box=box.ROUNDED,
            border_style="red",
            show_header=True,
            header_style="bold red",
        )
        v_table.add_column("Location", style="dim", max_width=60)
        v_table.add_column("Asset", style="bold red")
        v_table.add_column("Type", style="dim")
        v_table.add_column("Reason")

        for v in violations:
            v_table.add_row(v["location"], v["asset"], v["type"], v["reason"])

        console.print(v_table)
        console.print()

        # Show code snippets for violations
        for v in violations:
            if v.get("match"):
                console.print(f"  [red]\u2717[/] [bold]{v['location']}[/]")
                console.print(f"    [dim italic]{v['match'][:150]}[/]")
                console.print()

    # Warnings table
    if warnings:
        console.print(
            Rule("[bold yellow]WARNINGS (review recommended)[/]", style="yellow")
        )
        console.print()

        w_table = Table(
            box=box.ROUNDED,
            border_style="yellow",
            show_header=True,
            header_style="bold yellow",
        )
        w_table.add_column("Location", style="dim", max_width=60)
        w_table.add_column("Asset", style="bold yellow")
        w_table.add_column("Type", style="dim")
        w_table.add_column("Reason")

        for w in warnings:
            w_table.add_row(w["location"], w["asset"], w["type"], w["reason"])

        console.print(w_table)
        console.print()

        # Show PQC migration notes
        seen_notes = set()
        for w in warnings:
            note = w.get("note", "")
            if note and note not in seen_notes:
                seen_notes.add(note)
                console.print(f"  [yellow]\u26a0[/]  [italic]{note}[/]")
        if seen_notes:
            console.print()

    # Final verdict
    if violations:
        console.print(
            Panel(
                "[bold red]\u274c POLICY CHECK FAILED[/]\n\n"
                f"  {len(violations)} violation(s) must be resolved before merging.",
                border_style="red",
                box=box.DOUBLE,
            )
        )
    elif warnings:
        console.print(
            Panel(
                "[bold yellow]\u26a0\ufe0f  POLICY CHECK PASSED WITH WARNINGS[/]\n\n"
                f"  {len(warnings)} warning(s) should be reviewed.",
                border_style="yellow",
                box=box.DOUBLE,
            )
        )
    else:
        console.print(
            Panel(
                "[bold green]\u2705 POLICY CHECK PASSED[/]\n\n"
                "  All cryptographic assets comply with policy.",
                border_style="green",
                box=box.DOUBLE,
            )
        )

    console.print()


def main():
    if len(sys.argv) < 3:
        console.print(
            "[red]Usage: python policy-check.py <results.json> <policy.json>[/]"
        )
        console.print("[dim]  Exit code 0 = pass, 1 = violations found[/]")
        sys.exit(2)

    results_path = sys.argv[1]
    policy_path = sys.argv[2]

    for path in [results_path, policy_path]:
        if not os.path.exists(path):
            console.print(f"[red]File not found: {path}[/]")
            sys.exit(2)

    results = load_json(results_path)
    policy = load_json(policy_path)

    total_assets = sum(
        len(f["cryptographic_assets"]) for f in results.get("findings", [])
    )

    violations, warnings = check_policy(results, policy)
    display_results(policy, violations, warnings, total_assets)

    if violations:
        sys.exit(1)
    sys.exit(0)


if __name__ == "__main__":
    main()
