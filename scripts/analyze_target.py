#!/usr/bin/env python3
"""
Target analysis script
Analyzes a target for vulnerabilities
"""

import argparse
import json
from pathlib import Path
import sys

# Add parent directory to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.inference.predictor import ThreatPredictor
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich.tree import Tree


console = Console()


def display_results(results: dict):
    """Display analysis results in a nice format"""
    
    # Header
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]")
    console.print(f"[bold cyan]BUGPREDICT AI - THREAT ANALYSIS REPORT[/bold cyan]")
    console.print(f"[bold cyan]{'='*70}[/bold cyan]\n")
    
    # Target info
    console.print(Panel(
        f"[bold]Target:[/bold] {results['target']}\n"
        f"[bold]Company:[/bold] {results['company']}\n"
        f"[bold]Technologies:[/bold] {', '.join(results['technology_stack'])}",
        title="Target Information",
        border_style="cyan"
    ))
    
    # Risk score
    risk_score = results['risk_score']
    risk_level = results['risk_level']
    
    risk_color = {
        'critical': 'red',
        'high': 'orange1',
        'medium': 'yellow',
        'low': 'green'
    }.get(risk_level, 'white')
    
    console.print(f"\n[bold]Risk Score:[/bold] [{risk_color}]{risk_score}/10 ({risk_level.upper()})[/{risk_color}]\n")
    
    # Vulnerability predictions
    console.print("[bold underline]Top Vulnerability Predictions:[/bold underline]\n")
    
    vuln_table = Table(show_header=True, header_style="bold magenta")
    vuln_table.add_column("Rank", style="dim", width=6)
    vuln_table.add_column("Vulnerability", width=25)
    vuln_table.add_column("Probability", justify="right", width=12)
    vuln_table.add_column("Confidence", width=12)
    vuln_table.add_column("Priority", justify="center", width=10)
    
    for idx, vuln in enumerate(results['vulnerability_predictions'][:10], 1):
        priority_stars = "⭐" * vuln['priority']
        
        vuln_table.add_row(
            str(idx),
            vuln['vulnerability_type'],
            f"{vuln['probability']:.1%}",
            vuln['confidence'],
            priority_stars
        )
    
    console.print(vuln_table)
    
    # Chains
    if results['chain_predictions']:
        console.print(f"\n[bold underline]Attack Chains Detected:[/bold underline]\n")
        
        for chain in results['chain_predictions'][:5]:
            console.print(
                f"  [red]⚠[/red] {chain['name']} "
                f"(Score: {chain['exploitability_score']}/10)"
            )
            console.print(f"     {chain['description']}")
            console.print()
    
    # Test strategy
    console.print("[bold underline]Recommended Test Strategy:[/bold underline]\n")
    
    strategy = results['test_strategy']
    
    for target in strategy['priority_targets'][:5]:
        console.print(f"[bold]{target['vulnerability']}[/bold] ({target['time_allocation']})")
        console.print(f"  Tools: {', '.join(target['tools'][:3])}")
        console.print()
    
    # Recommendations
    console.print("[bold underline]Recommendations:[/bold underline]\n")
    
    for i, rec in enumerate(results['recommendations'][:5], 1):
        console.print(f"  {i}. {rec}")
    
    console.print(f"\n[bold cyan]{'='*70}[/bold cyan]\n")


def main():
    parser = argparse.ArgumentParser(description='Analyze target for vulnerabilities')
    
    parser.add_argument(
        '--domain',
        '-d',
        required=True,
        help='Target domain (e.g., example.com)'
    )
    
    parser.add_argument(
        '--company',
        '-c',
        help='Company name'
    )
    
    parser.add_argument(
        '--tech',
        '-t',
        nargs='+',
        help='Technology stack (e.g., React Node.js PostgreSQL)'
    )
    
    parser.add_argument(
        '--endpoints',
        '-e',
        nargs='+',
        help='API endpoints to test'
    )
    
    parser.add_argument(
        '--auth',
        action='store_true',
        help='Target requires authentication'
    )
    
    parser.add_argument(
        '--api',
        action='store_true',
        help='Target has API endpoints'
    )
    
    parser.add_argument(
        '--output',
        '-o',
        help='Output file (JSON)'
    )
    
    parser.add_argument(
        '--models-dir',
        default='data/models',
        help='Directory containing trained models'
    )
    
    args = parser.parse_args()
    
    # Build target info
    target_info = {
        'domain': args.domain,
        'company_name': args.company or args.domain.split('.')[0].title(),
        'technology_stack': args.tech or [],
        'endpoints': args.endpoints or ['/'],
        'auth_required': args.auth,
        'has_api': args.api
    }
    
    # Load predictor
    console.print("[cyan]Loading models...[/cyan]")
    predictor = ThreatPredictor(models_dir=args.models_dir)
    
    # Analyze
    console.print(f"[cyan]Analyzing {args.domain}...[/cyan]")
    results = predictor.analyze_target(target_info)
    
    # Display results
    display_results(results)
    
    # Save to file
    if args.output:
        with open(args.output, 'w') as f:
            json.dump(results, f, indent=2)
        console.print(f"[green]✓ Results saved to {args.output}[/green]")


if __name__ == '__main__':
    main()
