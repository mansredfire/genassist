#!/usr/bin/env python3
"""
Visual data collection using mock data
Demonstrates the Rich Terminal UI with realistic fake data
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import time
import json
from datetime import datetime
from rich.console import Console
from rich.panel import Panel

# Import the mock data generator
from test_with_mock_data import generate_mock_reports

# Import the visual collector
from collect_data_visual import VisualCollector

console = Console()

def main():
    """Run visual collection with mock data"""
    
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Visual data collection with mock data'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=30,
        help='Number of reports to generate (default: 30)'
    )
    
    args = parser.parse_args()
    
    # Show banner
    console.print()
    console.print(Panel.fit(
        "[bold white]🤖 BugPredict AI[/bold white]\n"
        "[cyan]Visual Collection System[/cyan]\n"
        "[yellow](Using Mock Data)[/yellow]\n\n"
        f"Generating: {args.limit} reports",
        border_style="blue"
    ))
    console.print()
    
    # Generate mock reports
    console.print("[bold green]📊 Generating mock vulnerability reports...[/bold green]\n")
    reports = generate_mock_reports(count=args.limit)
    
    console.print(f"[bold green]✅ Generated {len(reports)} reports[/bold green]\n")
    time.sleep(1)
    
    # Create visual collector
    collector = VisualCollector()
    
    console.print("[bold cyan]🎨 Starting visual collection...[/bold cyan]\n")
    time.sleep(1)
    
    # Create layout (same as real collection)
    from rich.layout import Layout
    from rich.live import Live
    
    layout = Layout()
    layout.split_column(
        Layout(name="header", size=3),
        Layout(name="main"),
        Layout(name="current", size=12)
    )
    
    layout["main"].split_row(
        Layout(name="stats"),
        Layout(name="reports")
    )
    
    layout["stats"].split_column(
        Layout(name="collection_stats"),
        Layout(name="severity")
    )
    
    # Simulate streaming collection
    with Live(layout, refresh_per_second=4, console=console) as live:
        for report in reports:
            # Convert report to dict format
            report_dict = {
                'report_id': report.report_id,
                'source': 'HackerOne (Mock)',
                'time': datetime.now().strftime('%H:%M:%S'),
                'title': report.description,
                'vulnerability_type': report.vulnerability_type,
                'severity': report.severity,
                'bounty': report.bounty_amount,
                'company': report.target_company,
                'domain': report.target_domain
            }
            
            collector.collected_reports.append(report_dict)
            collector.stats['hackerone'] += 1
            collector.stats['total'] += 1
            
            # Update severity counts
            if report.severity in collector.stats:
                collector.stats[report.severity] += 1
            
            # Update layout
            layout["header"].update(collector.create_header())
            layout["collection_stats"].update(collector.create_stats_table())
            layout["severity"].update(collector.create_severity_panel())
            layout["reports"].update(collector.create_recent_reports_table())
            layout["current"].update(collector.create_current_report_panel(report_dict))
            
            time.sleep(0.3)  # Simulate collection delay
    
    # Show summary
    console.print()
    console.print(Panel.fit(
        f"[bold green]✅ Collection Complete![/bold green]\n\n"
        f"Total Reports: [bold]{collector.stats['total']}[/bold]\n"
        f"HackerOne: {collector.stats['hackerone']}\n\n"
        f"Critical: [red]{collector.stats['critical']}[/red]\n"
        f"High: [yellow]{collector.stats['high']}[/yellow]\n"
        f"Medium: [blue]{collector.stats['medium']}[/blue]\n"
        f"Low: [green]{collector.stats['low']}[/green]",
        title="📊 Summary",
        border_style="green"
    ))
    
    # Save results
    output_file = collector.save_results(output_dir='data/raw')
    
    console.print()
    console.print("[bold green]🎉 Visual collection demo complete![/bold green]")
    console.print("\n[dim]This was a demonstration using mock data.[/dim]")
    console.print("[dim]The real system will work the same way with live HackerOne data![/dim]\n")

if __name__ == "__main__":
    main()
