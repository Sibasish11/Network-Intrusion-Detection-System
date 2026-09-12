#!/usr/bin/env python3

import os
import sys
import time
import json
import random
import argparse
import warnings
warnings.filterwarnings("ignore")

import os
import sys
import time
import json
import random
import argparse
import warnings
warnings.filterwarnings("ignore")

# Force UTF-8 on Windows
if sys.platform == "win32":
    try:
        sys.stdout.reconfigure(encoding="utf-8", errors="replace")
        sys.stderr.reconfigure(encoding="utf-8", errors="replace")
        if hasattr(sys.stdin, "reconfigure"):
            sys.stdin.reconfigure(encoding="utf-8", errors="replace")
    except Exception:
        pass

# Rich Terminal UI components
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.markdown import Markdown
from rich.prompt import Prompt, Confirm, IntPrompt, FloatPrompt
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, TimeRemainingColumn
from rich.align import Align
from rich import box

# Ensure project root is in python path
BASE_DIR = os.path.dirname(os.path.abspath(__file__))
if BASE_DIR not in sys.path:
    sys.path.insert(0, BASE_DIR)

from src.engine import (
    get_engine, PRESETS, DISPLAY_COLS,
    get_ai_explanation, ask_soc_analyst_chat,
    generate_firewall_rules,
    get_stored_gemini_key, set_stored_gemini_key,
    load_config, save_config
)

console = Console(force_terminal=True)


def print_banner():
    """Renders high-tech cybersecurity terminal banner."""
    banner_text = """
 [bold cyan] ███╗   ██╗██╗██████╗ ███████╗   ████████╗███████╗██████╗ ███╗   ███╗[/bold cyan]
 [bold cyan] ████╗  ██║██║██╔══██╗██╔════╝   ╚══██╔══╝██╔════╝██╔══██╗████╗ ████║[/bold cyan]
 [bold cyan] ██╔██╗ ██║██║██║  ██║███████╗█████╗██║   █████╗  ██████╔╝██╔████╔██║[/bold cyan]
 [bold cyan] ██║╚██╗██║██║██║  ██║╚════██║╚════╝██║   ██╔══╝  ██╔══██╗██║╚██╔╝██║[/bold cyan]
 [bold cyan] ██║ ╚████║██║██████╔╝███████║      ██║   ███████╗██║  ██║██║ ╚═╝ ██║[/bold cyan]
 [bold cyan] ╚═╝  ╚═══╝╚═╝╚═════╝ ╚══════╝      ╚═╝   ╚══════╝╚═╝  ╚═╝╚═╝     ╚═╝[/bold cyan]
    """
    console.print(banner_text, highlight=False)
    
    # Status bar
    key_status = "[bold green]Configured[/bold green]" if get_stored_gemini_key() else "[dim yellow]Local Heuristics[/dim yellow]"
    status_table = Table(box=box.HORIZONTALS, show_header=False, expand=True, padding=(0, 1))
    status_table.add_column("Key", style="dim cyan", justify="left")
    status_table.add_column("Val", style="bold white", justify="right")
    status_table.add_row("🛡️ System", "[bold green]Active (Decision Tree + Random Forest + Naive Bayes)[/bold green]")
    status_table.add_row("🤖 AI Reasoning Engine", f"Gemini 2.5 / Heuristics ({key_status})")
    status_table.add_row("📡 Dataset", "NSL-KDD Benchmark (41 Dimensions)")
    
    console.print(Panel(status_table, title="[bold cyan]⚡ AI POWERED NETWORK INTRUSION DETECTION CONSOLE [/bold cyan]", border_style="cyan", padding=(0, 1)))


def render_threat_gauge(threat_score):
    """Draws a visual ASCII gauge for threat score."""
    total_bars = 20
    filled = int(round((threat_score / 100.0) * total_bars))
    empty = total_bars - filled
    
    if threat_score >= 70:
        bar_color = "bold red"
        status_tag = "[bold red]CRITICAL THREAT[/bold red]"
    elif threat_score >= 40:
        bar_color = "bold yellow"
        status_tag = "[bold yellow]SUSPICIOUS ANOMALY[/bold yellow]"
    else:
        bar_color = "bold green"
        status_tag = "[bold green]BENIGN / NORMAL[/bold green]"
        
    gauge = f"[{bar_color}]{'█' * filled}[/{bar_color}][dim white]{'░' * empty}[/dim white] [bold white]{threat_score:5.1f}%[/bold white] ({status_tag})"
    return gauge


def display_telemetry_results(result, raw_features, ground_truth=None, ai_text=None, title="TELEMETRY SCAN RESULT"):
    """Renders complete, gorgeous analysis card in terminal."""
    is_attack = result["consensus_verdict"] == "attack"
    verdict_style = "bold white on red" if is_attack else "bold white on green"
    verdict_icon = "MALICIOUS ATTACK DETECTED" if is_attack else "BENIGN / SAFE NETWORK TRAFFIC"
    
    console.print()
    # 1. Main Verdict Header
    attack_votes = result.get("attack_votes", 0)
    total_models = result.get("total_models", len(result.get("predictions", {})))
    unanimous_str = "Unanimous" if attack_votes in (0, total_models) else "Split Decision"

    verdict_panel = Panel(
        Align.center(f"[{verdict_style}]  {verdict_icon}  [/{verdict_style}]\n\nThreat Score: {render_threat_gauge(result['threat_score'])}\n" +
                     f"Consensus: [bold cyan]{attack_votes}/{total_models}[/bold cyan] Models Flagged Malicious ({unanimous_str})"),
        title=f"[bold cyan]🔍 {title}[/bold cyan]",
        border_style="red" if is_attack else "green",
        padding=(1, 2)
    )
    console.print(verdict_panel)

    # 2. Key Telemetry & Model Predictions Side-by-Side
    # Left: Features Table
    feat_table = Table(title="[bold cyan]Packet Features[/bold cyan]", box=box.ROUNDED, show_header=True)
    feat_table.add_column("Parameter", style="dim cyan")
    feat_table.add_column("Value", style="bold white")
    
    for k in DISPLAY_COLS:
        if k in raw_features:
            val = raw_features[k]
            # Color highlights for key parameters
            if k == "flag" and val in ["S0", "REJ", "RSTO"]:
                val_str = f"[bold red]{val}[/bold red]"
            elif k in ["serror_rate", "rerror_rate"] and float(val) > 0.3:
                val_str = f"[bold red]{val}[/bold red]"
            elif k in ["num_failed_logins", "root_shell"] and int(val) > 0:
                val_str = f"[bold red]{val}[/bold red]"
            else:
                val_str = str(val)
            feat_table.add_row(k, val_str)

    # Right: Multi-Model Vote Table
    model_table = Table(title="[bold cyan]Machine Learning Predictions[/bold cyan]", box=box.ROUNDED, show_header=True)
    model_table.add_column("Model", style="cyan")
    model_table.add_column("Verdict", justify="center")
    model_table.add_column("Confidence", justify="right")
    model_table.add_column("Attack Prob", justify="right")
    if ground_truth:
        model_table.add_column("Accuracy", justify="center")

    for name, pred in result["predictions"].items():
        v_tag = "[bold red]ATTACK[/bold red]" if pred["prediction"] == "attack" else "[bold green]NORMAL[/bold green]"
        conf_str = f"{pred['confidence'] * 100:.1f}%"
        prob_str = f"{pred['attack_probability'] * 100:.1f}%"
        
        row_args = [name.replace("_", " ").title(), v_tag, conf_str, prob_str]
        if ground_truth:
            match = pred["prediction"] == ground_truth
            match_str = "[bold green]MATCH ✓[/bold green]" if match else "[bold red]MISMATCH ✗[/bold red]"
            row_args.append(match_str)
            
        model_table.add_row(*row_args)

    # Risk Factors List
    risk_table = Table(title="[bold yellow]Heuristic Telemetry Risk Indicators[/bold yellow]", box=box.ROUNDED, show_header=True)
    risk_table.add_column("Severity", style="bold", justify="center", width=12)
    risk_table.add_column("Indicator & Findings", style="white")

    risks = result.get("risk_factors", [])
    if risks:
        for r in risks:
            sev = r.get("severity", "info").upper()
            if sev == "CRITICAL":
                sev_str = "[bold white on red]CRITICAL[/bold white on red]"
            elif sev == "HIGH":
                sev_str = "[bold red]HIGH[/bold red]"
            elif sev == "MEDIUM":
                sev_str = "[bold yellow]MEDIUM[/bold yellow]"
            else:
                sev_str = "[bold green]INFO[/bold green]"
            risk_table.add_row(sev_str, f"[bold]{r['title']}[/bold]\n[dim]{r['desc']}[/dim]")
    else:
        risk_table.add_row("[bold green]INFO[/bold green]", "Standard benign traffic signatures. No anomalies detected.")

    console.print(feat_table)
    console.print(model_table)
    console.print(risk_table)

    # 3. Ground Truth Banner (if available)
    if ground_truth:
        gt_color = "red" if ground_truth == "attack" else "green"
        console.print(Panel(
            f"Ground Truth Dataset Label: [bold {gt_color}]{ground_truth.upper()}[/bold {gt_color}]",
            border_style=gt_color,
            padding=(0, 1)
        ))

    # 4. AI SOC Analyst Diagnosis
    if ai_text:
        console.print()
        ai_panel = Panel(
            Markdown(ai_text),
            title="[bold magenta] AI SOC Analyst Deep Telemetry Reasoning[/bold magenta]",
            border_style="magenta",
            padding=(1, 2)
        )
        console.print(ai_panel)


# =====================================================================
# INTERACTIVE WORKFLOWS
# =====================================================================

def interactive_presets():
    """Menu 1: Run realistic attack presets."""
    engine = get_engine()
    console.print("\n[bold cyan]Available Network Traffic & Attack Presets:[/bold cyan]\n")
    
    table = Table(box=box.ROUNDED, show_header=True)
    table.add_column("#", style="bold cyan", width=4)
    table.add_column("Preset Name", style="bold white")
    table.add_column("Category", style="cyan")
    table.add_column("Type", justify="center")
    table.add_column("Description", style="dim")

    for i, p in enumerate(PRESETS, 1):
        type_str = "[bold red]ATTACK[/bold red]" if p["type"] == "attack" else "[bold green]NORMAL[/bold green]"
        table.add_row(str(i), p["name"], p["category"], type_str, p["description"])

    console.print(table)
    
    choice = Prompt.ask("\nSelect preset number to analyze (or 0 to return)", default="1")
    if choice == "0" or not choice.isdigit():
        return

    idx = int(choice) - 1
    if 0 <= idx < len(PRESETS):
        preset = PRESETS[idx]
        with console.status(f"[bold cyan]Running AI & Multi-Model Telemetry on '{preset['name']}'...[/bold cyan]"):
            result = engine.predict_features(preset["features"])
            risks = engine.extract_risk_factors(preset["features"])
            result["risk_factors"] = risks
            ai_text = get_ai_explanation(
                features=preset["features"],
                true_label=preset["type"],
                predictions=result["predictions"],
                consensus_verdict=result["consensus_verdict"],
                threat_score=result["threat_score"]
            )
        display_telemetry_results(result, preset["features"], ground_truth=preset["type"], ai_text=ai_text, title=f"PRESET SCAN: {preset['name']}")
    else:
        console.print("[red]Invalid selection.[/red]")


def interactive_manual_inspector():
    """Menu 2: Interactively craft network features."""
    engine = get_engine()
    console.print("\n[bold cyan] Interactive Traffic Packet Builder[/bold cyan]")
    console.print("[dim]Press Enter to accept default values, or enter custom parameters:[/dim]\n")

    protocols = ["tcp", "udp", "icmp"]
    services = ["http", "ftp", "smtp", "telnet", "ssh", "domain_u", "private", "ecr_i", "other"]
    flags = ["SF", "S0", "REJ", "RSTO", "RSTR", "S1", "S2", "S3"]

    protocol = Prompt.ask("Protocol Type", choices=protocols, default="tcp")
    service = Prompt.ask(f"Service ({', '.join(services[:5])}...)", default="http")
    flag = Prompt.ask("TCP Connection Flag", choices=flags, default="SF")
    duration = FloatPrompt.ask("Connection Duration (seconds)", default=0.0)
    src_bytes = FloatPrompt.ask("Source Bytes Payload", default=300.0)
    dst_bytes = FloatPrompt.ask("Destination Bytes Payload", default=4500.0)
    logged_in = IntPrompt.ask("Authentication Logged In (1=Yes, 0=No)", default=1)
    failed_logins = IntPrompt.ask("Number of Failed Login Attempts", default=0)
    root_shell = IntPrompt.ask("Root Shell Executed (1=Yes, 0=No)", default=0)
    count = FloatPrompt.ask("Connection Count in Past 2-Sec Window", default=10.0)
    serror_rate = FloatPrompt.ask("SYN Error Rate (0.0 to 1.0)", default=0.0)
    rerror_rate = FloatPrompt.ask("REJ Error Rate (0.0 to 1.0)", default=0.0)

    user_features = {
        "protocol_type": protocol,
        "service": service,
        "flag": flag,
        "duration": duration,
        "src_bytes": src_bytes,
        "dst_bytes": dst_bytes,
        "logged_in": logged_in,
        "num_failed_logins": failed_logins,
        "root_shell": root_shell,
        "count": count,
        "serror_rate": serror_rate,
        "rerror_rate": rerror_rate,
        "same_srv_rate": 1.0 if rerror_rate == 0 else 0.05,
        "diff_srv_rate": 0.0 if rerror_rate == 0 else 0.7,
        "dst_host_count": 30,
        "dst_host_srv_count": 255 if rerror_rate == 0 else 2,
        "dst_host_same_srv_rate": 1.0 if rerror_rate == 0 else 0.05,
        "dst_host_diff_srv_rate": 0.0 if rerror_rate == 0 else 0.1,
        "dst_host_serror_rate": serror_rate,
        "dst_host_rerror_rate": rerror_rate,
    }

    with console.status("[bold cyan]Processing features and running ML models...[/bold cyan]"):
        result = engine.predict_features(user_features)
        risks = engine.extract_risk_factors(user_features)
        result["risk_factors"] = risks
        ai_text = get_ai_explanation(
            features=user_features,
            true_label=None,
            predictions=result["predictions"],
            consensus_verdict=result["consensus_verdict"],
            threat_score=result["threat_score"]
        )

    display_telemetry_results(result, user_features, ground_truth=None, ai_text=ai_text, title="CUSTOM TELEMETRY INSPECTION")


def interactive_dataset_sample():
    """Menu 3: Pull random sample from test dataset."""
    engine = get_engine()
    total = len(engine.X_test)
    console.print(f"\n[cyan]Pulling sample from test dataset ([bold white]{total}[/bold white] total benchmark records)...[/cyan]")
    
    custom_idx = Prompt.ask("Enter sample index (or press Enter for random sample)", default="")
    idx = int(custom_idx) if custom_idx.isdigit() else None

    with console.status("[bold cyan]Retrieving record and generating AI telemetry analysis...[/bold cyan]"):
        sample = engine.get_sample(index=idx)
        ai_text = get_ai_explanation(
            features=sample["features"],
            true_label=sample["true_label"],
            predictions=sample["predictions"],
            consensus_verdict=sample["consensus_verdict"],
            threat_score=sample["threat_score"]
        )

    display_telemetry_results(
        sample,
        sample["features"],
        ground_truth=sample["true_label"],
        ai_text=ai_text,
        title=f"TEST DATASET RECORD #{sample['sample_index']}"
    )


def interactive_traffic_simulator():
    """Menu 4: Stream live simulated packet flows with real-time detection."""
    engine = get_engine()
    console.print("\n[bold cyan] Live Network Traffic Stream Simulator[/bold cyan]")
    console.print("[dim]Streams incoming packets through Decision Tree, Random Forest, and Naive Bayes in real time.[/dim]\n")

    count = IntPrompt.ask("How many packets to stream?", default=10)
    delay = FloatPrompt.ask("Delay between packets in seconds", default=0.5)
    attacks_only = Confirm.ask("Display flagged attacks only?", default=False)

    console.print("\n[bold green]Starting live network packet capture stream... (Ctrl+C to pause)[/bold green]\n")
    
    stream_table = Table(box=box.SIMPLE_HEAD, show_header=True, expand=True)
    stream_table.add_column("Time", style="dim", width=10)
    stream_table.add_column("Proto/Service", style="cyan", width=16)
    stream_table.add_column("Flag", width=6)
    stream_table.add_column("Bytes In/Out", justify="right", width=16)
    stream_table.add_column("Threat", justify="right", width=10)
    stream_table.add_column("Consensus Verdict", justify="center", width=18)
    stream_table.add_column("Ground Truth", justify="center", width=14)

    attack_count = 0
    total_processed = 0

    try:
        for i in range(count):
            sample = engine.get_sample()
            total_processed += 1
            is_attack = sample["consensus_verdict"] == "attack"
            if is_attack:
                attack_count += 1

            if attacks_only and not is_attack:
                time.sleep(delay)
                continue

            # Format row
            t_stamp = time.strftime("%H:%M:%S")
            proto_srv = f"{sample['features'].get('protocol_type', 'tcp')}/{sample['features'].get('service', 'http')}"
            flag = sample['features'].get('flag', 'SF')
            bytes_str = f"{int(sample['features'].get('src_bytes', 0))}/{int(sample['features'].get('dst_bytes', 0))}"
            
            score_color = "red" if sample["threat_score"] >= 60 else ("yellow" if sample["threat_score"] >= 30 else "green")
            threat_str = f"[{score_color}]{sample['threat_score']:.1f}%[/{score_color}]"
            
            v_badge = "[bold red]🚨 ATTACK[/bold red]" if is_attack else "[bold green]🛡️ BENIGN[/bold green]"
            gt_badge = "[red]attack[/red]" if sample["true_label"] == "attack" else "[green]normal[/green]"

            console.print(f"[{t_stamp}] [bold cyan]{proto_srv:14s}[/bold cyan] [yellow]{flag:4s}[/yellow] "
                          f"Bytes: {bytes_str:14s} Score: {threat_str:16s} Verdict: {v_badge:20s} GroundTruth: {gt_badge}")
            
            time.sleep(delay)

    except KeyboardInterrupt:
        console.print("\n[yellow]Packet stream paused by user.[/yellow]")

    console.print(Panel(
        f"Stream Summary: [bold cyan]{total_processed}[/bold cyan] Packets Analyzed | "
        f"[bold red]{attack_count}[/bold red] Malicious Incursions Intercepted | "
        f"[bold green]{total_processed - attack_count}[/bold green] Benign Operations",
        title="[bold cyan]Stream Statistics[/bold cyan]",
        border_style="cyan"
    ))


def interactive_model_evaluation():
    """Menu 5: Model Performance & Evaluation Dashboard."""
    engine = get_engine()
    with console.status("[bold cyan]Running batch evaluation across entire test dataset...[/bold cyan]"):
        metrics = engine.evaluate_all_models()

    console.print("\n[bold cyan]📊 Model Performance & Benchmark Evaluation Matrix[/bold cyan]\n")
    
    summary_table = Table(box=box.ROUNDED, show_header=True)
    summary_table.add_column("Model Name", style="bold cyan")
    summary_table.add_column("Accuracy", justify="right")
    summary_table.add_column("Precision (Attack)", justify="right")
    summary_table.add_column("Recall (Attack)", justify="right")
    summary_table.add_column("F1-Score", justify="right")

    for name, m in metrics.items():
        summary_table.add_row(
            name.replace("_", " ").title(),
            f"{m['accuracy'] * 100:.2f}%",
            f"{m['precision'] * 100:.2f}%",
            f"{m['recall'] * 100:.2f}%",
            f"[bold green]{m['f1'] * 100:.2f}%[/bold green]"
        )

    console.print(summary_table)

    # Display ANSI Confusion Matrices
    console.print("\n[bold cyan] Confusion Matrices (Attack vs Normal):[/bold cyan]")
    for name, m in metrics.items():
        cm = m["confusion_matrix"]
        cm_table = Table(title=f"Confusion Matrix: [bold yellow]{name.replace('_', ' ').title()}[/bold yellow]", box=box.SIMPLE)
        cm_table.add_column("", style="dim")
        cm_table.add_column("Pred: Attack", justify="right", style="bold red")
        cm_table.add_column("Pred: Normal", justify="right", style="bold green")
        
        cm_table.add_row("[bold red]Actual: Attack[/bold red]", str(cm[0][0]), str(cm[0][1]))
        cm_table.add_row("[bold green]Actual: Normal[/bold green]", str(cm[1][0]), str(cm[1][1]))
        console.print(cm_table)


def interactive_soc_chat():
    """Menu 6: Interactive SOC Analyst Terminal Chat."""
    engine = get_engine()
    console.print("\n[bold magenta] Interactive SOC Analyst Terminal Cyber Assistant[/bold magenta]")
    console.print("[dim]Ask any cybersecurity question, packet analysis inquiry, or request firewall rules (iptables/snort). Type 'exit' to return.[/dim]\n")
    
    # Use the most recent preset as context if available
    context = {
        "consensus_verdict": "attack",
        "threat_score": 94.2,
        "features": PRESETS[2]["features"],
        "predictions": {
            "decision_tree": {"prediction": "attack", "confidence": 0.99},
            "random_forest": {"prediction": "attack", "confidence": 0.98},
            "naive_bayes": {"prediction": "attack", "confidence": 0.85}
        }
    }

    while True:
        try:
            user_msg = Prompt.ask("[bold magenta]SOC Analyst >[/bold magenta]")
            if not user_msg or user_msg.strip().lower() in ["exit", "quit", "q", "back"]:
                break

            with console.status("[bold magenta]SOC Analyst is thinking & synthesizing response...[/bold magenta]"):
                reply = ask_soc_analyst_chat(user_msg, context=context)

            console.print()
            console.print(Panel(Markdown(reply), title="[bold magenta] Incident Responder Response[/bold magenta]", border_style="magenta", padding=(1, 2)))
            console.print()
        except KeyboardInterrupt:
            break


def interactive_firewall_generator():
    """Menu 7: Instant Firewall Rule Generator."""
    console.print("\n[bold cyan]🛡️ Instant Firewall Rule Generator[/bold cyan]")
    console.print("Select an attack profile to generate defensive mitigation rules:\n")
    
    for i, p in enumerate(PRESETS, 1):
        console.print(f" [bold cyan]{i}[/bold cyan]. {p['name']} ({p['category']})")

    choice = Prompt.ask("\nSelect preset number", default="3")
    if not choice.isdigit():
        return
    idx = int(choice) - 1
    if 0 <= idx < len(PRESETS):
        preset = PRESETS[idx]
        rules = generate_firewall_rules(preset["features"], preset["type"])
        
        console.print(f"\n[bold green]Generated Firewall Defense Rules for: {preset['name']}[/bold green]\n")
        
        console.print(Panel(f"```bash\n{rules['iptables']}\n```", title="[bold cyan]Linux iptables ACL Rules[/bold cyan]", border_style="cyan"))
        console.print(Panel(f"```snort\n{rules['snort']}\n```", title="[bold yellow]Snort IDS Rule Signatures[/bold yellow]", border_style="yellow"))
        if rules.get("nftables"):
            console.print(Panel(f"```nftables\n{rules['nftables']}\n```", title="[bold green]nftables Rules[/bold green]", border_style="green"))
    else:
        console.print("[red]Invalid selection.[/red]")


def interactive_settings():
    """Menu 8: Configure Gemini API Key & Preferences."""
    console.print("\n[bold cyan]⚙️ Configuration & API Key Manager[/bold cyan]")
    current_key = get_stored_gemini_key()
    
    if current_key:
        masked = current_key[:6] + "..." + current_key[-4:] if len(current_key) > 10 else "***"
        console.print(f"Current Gemini API Key: [bold green]{masked}[/bold green]")
    else:
        console.print("Current Gemini API Key: [dim yellow]Not Configured (Operating in Local Heuristic Mode)[/dim yellow]")

    console.print("\nOptions:")
    console.print(" 1. Set / Update Gemini API Key")
    console.print(" 2. Remove Gemini API Key (revert to local mode)")
    console.print(" 0. Back to Main Menu")

    choice = Prompt.ask("\nSelect option", default="0")
    if choice == "1":
        new_key = Prompt.ask("Enter your Google Gemini API Key (paste silently)", password=True)
        if new_key and new_key.strip():
            set_stored_gemini_key(new_key.strip())
            console.print("[bold green]✓ Gemini API Key successfully saved to .nids_config.json![/bold green]")
    elif choice == "2":
        set_stored_gemini_key("")
        console.print("[bold yellow]Gemini API Key removed. Engine is now in offline heuristic mode.[/bold yellow]")


def interactive_retrain_models():
    """Menu 9: Retrain all 3 ML models from scratch."""
    if not Confirm.ask("[bold yellow]Are you sure you want to retrain all models from raw dataset?[/bold yellow]", default=False):
        return
        
    from src.train import train_all
    with console.status("[bold cyan]Preprocessing NSL-KDD dataset and retraining models...[/bold cyan]"):
        train_all()
        # Reload engine
        get_engine().load_artifacts()
        
    console.print("\n[bold green]✓ All models successfully retrained and reloaded into memory![/bold green]")


# =====================================================================
# MAIN INTERACTIVE LOOP
# =====================================================================

def run_interactive_console():
    """Main interactive terminal application loop."""
    while True:
        console.clear()
        print_banner()
        
        console.print("[bold cyan]═══════════════════════════════════════════════════════════════════════[/bold cyan]")
        console.print(" [bold cyan]1.[/bold cyan] 🎯 [bold white]Run Attack Signature Presets[/bold white]       [dim](SYN Flood, Port Scan, FTP Brute Force...)[/dim]")
        console.print(" [bold cyan]2.[/bold cyan] 🧪 [bold white]Interactive Traffic Packet Builder[/bold white] [dim](Custom telemetry parameter inspection)[/dim]")
        console.print(" [bold cyan]3.[/bold cyan] 🎲 [bold white]Test Dataset Sample Inspector[/bold white]      [dim](Pull real benchmark records & compare GT)[/dim]")
        console.print(" [bold cyan]4.[/bold cyan] ⚡ [bold white]Live Traffic Stream Simulator[/bold white]      [dim](Real-time streaming packet detection)[/dim]")
        console.print(" [bold cyan]5.[/bold cyan] 📊 [bold white]Model Performance & Evaluation[/bold white]     [dim](Accuracy, Precision, Recall, Confusion Matrix)[/dim]")
        console.print(" [bold cyan]6.[/bold cyan] 🤖 [bold white]AI SOC Analyst Terminal Chat[/bold white]       [dim](Conversational incident response & rules)[/dim]")
        console.print(" [bold cyan]7.[/bold cyan] 🛡️ [bold white]Instant Firewall Rule Generator[/bold white]    [dim](iptables, Snort, nftables synthesis)[/dim]")
        console.print(" [bold cyan]8.[/bold cyan] ⚙️ [bold white]API Key & System Settings[/bold white]          [dim](Configure Gemini / OpenAI keys)[/dim]")
        console.print(" [bold cyan]9.[/bold cyan] 🏋️ [bold white]Retrain Machine Learning Models[/bold white]    [dim](Re-run training pipeline)[/dim]")
        console.print(" [bold cyan]0.[/bold cyan] 🚪 [bold red]Exit Console[/bold red]")
        console.print("[bold cyan]═══════════════════════════════════════════════════════════════════════[/bold cyan]")
        
        choice = Prompt.ask("\n[bold cyan]Select an option[/bold cyan]", default="1")
        
        if choice == "1":
            interactive_presets()
        elif choice == "2":
            interactive_manual_inspector()
        elif choice == "3":
            interactive_dataset_sample()
        elif choice == "4":
            interactive_traffic_simulator()
        elif choice == "5":
            interactive_model_evaluation()
        elif choice == "6":
            interactive_soc_chat()
        elif choice == "7":
            interactive_firewall_generator()
        elif choice == "8":
            interactive_settings()
        elif choice == "9":
            interactive_retrain_models()
        elif choice in ["0", "exit", "quit", "q"]:
            console.print("\n[bold cyan]Exiting NIDS Console. Stay secure! 🛡️[/bold cyan]\n")
            break
        else:
            console.print("[red]Invalid selection, please try again.[/red]")

        console.print("\n[dim]Press Enter to continue...[/dim]")
        try:
            input()
        except (KeyboardInterrupt, EOFError):
            break


# =====================================================================
# CLI SUBCOMMAND PARSER
# =====================================================================

def parse_args_and_run():
    parser = argparse.ArgumentParser(
        description="NIDS Cyber Terminal — AI-Powered Network Intrusion Detection System CLI"
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # interactive
    subparsers.add_parser("interactive", help="Launch the rich interactive cyber console")

    # presets
    subparsers.add_parser("presets", help="List all available network traffic and attack presets")

    # predict
    predict_p = subparsers.add_parser("predict", help="Predict on a preset or custom telemetry")
    predict_p.add_argument("--preset", type=str, help="ID of preset to run (e.g. syn_flood, port_scan, normal_http)")
    predict_p.add_argument("--protocol", type=str, default="tcp", help="Protocol: tcp, udp, icmp")
    predict_p.add_argument("--service", type=str, default="http", help="Service name (e.g. http, ftp, ssh)")
    predict_p.add_argument("--flag", type=str, default="SF", help="Flag (e.g. SF, S0, REJ)")
    predict_p.add_argument("--gemini-key", type=str, help="Gemini API Key override")

    # sample
    sample_p = subparsers.add_parser("sample", help="Pull and analyze random sample from test dataset")
    sample_p.add_argument("--index", type=int, help="Sample index in dataset")
    sample_p.add_argument("--count", type=int, default=1, help="Number of samples to pull")
    sample_p.add_argument("--json", action="store_true", help="Output results in JSON format")

    # simulate
    sim_p = subparsers.add_parser("simulate", help="Stream live simulated packet traffic")
    sim_p.add_argument("--count", type=int, default=10, help="Number of packets to stream")
    sim_p.add_argument("--delay", type=float, default=0.4, help="Delay in seconds between packets")
    sim_p.add_argument("--attacks-only", action="store_true", help="Filter and show only attacks")

    # evaluate
    subparsers.add_parser("evaluate", help="Evaluate all 3 ML models against full test dataset")

    # train
    train_p = subparsers.add_parser("train", help="Retrain ML models")
    train_p.add_argument("--data-dir", type=str, default="data", help="Path to data directory")

    # chat
    chat_p = subparsers.add_parser("chat", help="Start interactive AI SOC analyst terminal chat")
    chat_p.add_argument("--key", type=str, help="Gemini API key override")

    # config
    config_p = subparsers.add_parser("config", help="Manage local configuration and API keys")
    config_p.add_argument("--set-key", type=str, help="Save Gemini API key")
    config_p.add_argument("--show", action="store_true", help="Show current config status")

    args = parser.parse_args()

    # If no subcommand provided, launch interactive console
    if not args.command or args.command == "interactive":
        run_interactive_console()
        return

    engine = get_engine()

    if args.command == "presets":
        table = Table(title="[bold cyan]Available NIDS Presets[/bold cyan]", box=box.ROUNDED)
        table.add_column("ID", style="bold cyan")
        table.add_column("Name", style="bold white")
        table.add_column("Type", justify="center")
        table.add_column("Description", style="dim")
        for p in PRESETS:
            t_str = "[red]ATTACK[/red]" if p["type"] == "attack" else "[green]NORMAL[/green]"
            table.add_row(p["id"], p["name"], t_str, p["description"])
        console.print(table)

    elif args.command == "predict":
        if args.preset:
            p_match = next((p for p in PRESETS if p["id"] == args.preset), None)
            if not p_match:
                console.print(f"[red]Error: Preset '{args.preset}' not found. Run 'python cli.py presets' to see options.[/red]")
                return
            features = p_match["features"]
            gt = p_match["type"]
            title = f"PRESET: {p_match['name']}"
        else:
            features = {"protocol_type": args.protocol, "service": args.service, "flag": args.flag}
            gt = None
            title = "CLI CUSTOM TELEMETRY PREDICTION"

        result = engine.predict_features(features)
        risks = engine.extract_risk_factors(features)
        result["risk_factors"] = risks
        ai_text = get_ai_explanation(
            features=features,
            true_label=gt,
            predictions=result["predictions"],
            consensus_verdict=result["consensus_verdict"],
            threat_score=result["threat_score"],
            client_api_key=args.gemini_key
        )
        display_telemetry_results(result, features, ground_truth=gt, ai_text=ai_text, title=title)

    elif args.command == "sample":
        count = args.count
        for i in range(count):
            sample = engine.get_sample(index=args.index if count == 1 else None)
            if args.json:
                print(json.dumps(sample, indent=2))
            else:
                ai_text = get_ai_explanation(
                    features=sample["features"],
                    true_label=sample["true_label"],
                    predictions=sample["predictions"],
                    consensus_verdict=sample["consensus_verdict"],
                    threat_score=sample["threat_score"]
                )
                display_telemetry_results(
                    sample,
                    sample["features"],
                    ground_truth=sample["true_label"],
                    ai_text=ai_text,
                    title=f"SAMPLE #{sample['sample_index']} ({i+1}/{count})"
                )

    elif args.command == "simulate":
        interactive_traffic_simulator()

    elif args.command == "evaluate":
        interactive_model_evaluation()

    elif args.command == "train":
        from src.train import train_all
        train_all(args.data_dir)
        console.print("[bold green]✓ Training completed.[/bold green]")

    elif args.command == "chat":
        interactive_soc_chat()

    elif args.command == "config":
        if args.set_key is not None:
            set_stored_gemini_key(args.set_key)
            console.print("[bold green]✓ Gemini API key saved.[/bold green]")
        if args.show or args.set_key is None:
            key = get_stored_gemini_key()
            if key:
                masked = key[:6] + "..." + key[-4:] if len(key) > 10 else "***"
                console.print(f"Gemini API Key: [bold green]{masked}[/bold green]")
            else:
                console.print("Gemini API Key: [yellow]Not configured (offline heuristics mode)[/yellow]")


if __name__ == "__main__":
    parse_args_and_run()
