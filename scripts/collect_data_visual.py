#!/usr/bin/env python3
"""
Visual data collection with Rich terminal UI
Beautiful real-time display of scraping progress
"""

import os
import sys
import time
import json
from pathlib import Path
from datetime import datetime

# Add project root to path
sys.path.insert(0, str(Path(__file__).parent.parent))

from rich.console import Console
from rich.table import Table
from rich.live import Live
from rich.panel import Panel
from rich.layout import Layout
from rich.text import Text
from rich.progress import Progress, SpinnerColumn, BarColumn, TextColumn, TimeRemainingColumn

console = Console()

class VisualCollector:
    """Visual data collector with Rich UI"""
    
    def __init__(self):
        self.collected_reports = []
        self.stats = {
            'total': 0,
            'hackerone': 0,
            'bugcrowd': 0,
            'cve': 0,
            'critical': 0,
            'high': 0,
            'medium': 0,
            'low': 0
        }
        self.start_time = time.time()
    
    def create_header(self):
        """Create header panel"""
        elapsed = int(time.time() - self.start_time)
        mins, secs = divmod(elapsed, 60)
        
        text = Text()
        text.append("🤖 BugPredict AI ", style="bold white")
        text.append("- Visual Data Collection\n", style="bold cyan")
        text.append(f"Started: {datetime.now().strftime('%H:%M:%S')} | ", style="dim")
        text.append(f"Elapsed: {mins:02d}:{secs:02d} | ", style="dim")
        text.append(f"Rate: {self.get_rate():.1f} reports/min", style="dim")
        
        return Panel(text, border_style="blue")
    
    def get_rate(self):
        """Calculate collection rate"""
        elapsed = time.time() - self.start_time
        if elapsed < 1:
            return 0
        return (self.stats['total'] / elapsed) * 60
    
    def create_stats_table(self):
        """Create statistics table"""
        table = Table(show_header=True, header_style="bold cyan", border_style="blue")
        table.add_column("Source", style="cyan", width=15)
        table.add_column("Count", justify="right", style="green", width=10)
        table.add_column("Percentage", justify="right", style="yellow", width=12)
        
        total = self.stats['total'] or 1  # Avoid division by zero
        
        table.add_row(
            "HackerOne", 
            str(self.stats['hackerone']),
            f"{(self.stats['hackerone']/total*100):.1f}%"
        )
        table.add_row(
            "Bugcrowd", 
            str(self.stats['bugcrowd']),
            f"{(self.stats['bugcrowd']/total*100):.1f}%"
        )
        table.add_row(
            "CVE/NVD", 
            str(self.stats['cve']),
            f"{(self.stats['cve']/total*100):.1f}%"
        )
        table.add_row("─" * 15, "─" * 10, "─" * 12, style="dim")
        table.add_row(
            "Total", 
            str(self.stats['total']),
            "100.0%",
            style="bold green"
        )
        
        return Panel(table, title="📊 Collection Stats", border_style="green")
    
    def create_severity_panel(self):
        """Create severity distribution panel"""
        
        def get_bar(count, max_count):
            """Create a simple bar chart"""
            if max_count == 0:
                return ""
            bar_length = int((count / max_count) * 20)
            return "█" * bar_length
        
        max_count = max(
            self.stats['critical'],
            self.stats['high'],
            self.stats['medium'],
            self.stats['low'],
            1
        )
        
        text = Text()
        text.append("🔴 Critical: ", style="bold red")
        text.append(f"{self.stats['critical']:3d} ", style="red")
        text.append(get_bar(self.stats['critical'], max_count), style="red")
        text.append("\n")
        
        text.append("🟠 High:     ", style="bold yellow")
        text.append(f"{self.stats['high']:3d} ", style="yellow")
        text.append(get_bar(self.stats['high'], max_count), style="yellow")
        text.append("\n")
        
        text.append("🟡 Medium:   ", style="bold blue")
        text.append(f"{self.stats['medium']:3d} ", style="blue")
        text.append(get_bar(self.stats['medium'], max_count), style="blue")
        text.append("\n")
        
        text.append("🟢 Low:      ", style="bold green")
        text.append(f"{self.stats['low']:3d} ", style="green")
        text.append(get_bar(self.stats['low'], max_count), style="green")
        
        return Panel(text, title="⚠️  Severity Distribution", border_style="yellow")
    
    def create_recent_reports_table(self, limit=10):
        """Create table of most recent reports"""
        table = Table(
            show_header=True, 
            header_style="bold magenta",
            border_style="magenta"
        )
        table.add_column("Time", style="dim", width=8)
        table.add_column("Source", style="cyan", width=12)
        table.add_column("Type", style="magenta", width=22)
        table.add_column("Sev", width=8)
        table.add_column("Title", style="white")
        
        recent = self.collected_reports[-limit:] if self.collected_reports else []
        
        for report in reversed(recent):  # Show newest first
            severity = report.get('severity', 'unknown').lower()
            severity_style = {
                'critical': 'bold red',
                'high': 'bold yellow',
                'medium': 'yellow',
                'low': 'green'
            }.get(severity, 'white')
            
            # Truncate long vulnerability types
            vuln_type = report.get('vulnerability_type', 'Unknown')
            if len(vuln_type) > 20:
                vuln_type = vuln_type[:17] + "..."
            
            # Truncate long titles
            title = report.get('title', 'No title')
            if len(title) > 45:
                title = title[:42] + "..."
            
            table.add_row(
                report.get('time', 'N/A'),
                report.get('source', 'N/A')[:10],
                vuln_type,
                Text(severity[:4].upper(), style=severity_style),
                title
            )
        
        return Panel(table, title="🔍 Recent Reports", border_style="magenta")
    
    def create_current_report_panel(self, report):
        """Create detailed preview of current report"""
        if not report:
            return Panel(
                "Waiting for reports...",
                title="📄 Current Report",
                border_style="blue"
            )
        
        severity = report.get('severity', 'unknown')
        severity_style = {
            'critical': 'bold red',
            'high': 'bold yellow',
            'medium': 'yellow',
            'low': 'green'
        }.get(severity.lower(), 'white')
        
        content = Text()
        content.append("Title: ", style="bold cyan")
        content.append(f"{report.get('title', 'N/A')}\n\n", style="white")
        
        content.append("Type: ", style="bold cyan")
        content.append(f"{report.get('vulnerability_type', 'N/A')}\n", style="magenta")
        
        content.append("Severity: ", style="bold cyan")
        content.append(f"{severity.upper()}\n", style=severity_style)
        
        content.append("Source: ", style="bold cyan")
        content.append(f"{report.get('source', 'N/A')}\n", style="cyan")
        
        if 'bounty' in report and report['bounty']:
            content.append("Bounty: ", style="bold cyan")
            content.append(f"${report['bounty']}\n", style="green")
        
        if 'description' in report and report['description']:
            desc = report['description'][:150]
            if len(report['description']) > 150:
                desc += "..."
            content.append("\nDescription: ", style="bold cyan")
            content.append(desc, style="dim")
        
        return Panel(content, title="📄 Current Report", border_style="blue")
    
    def collect_from_hackerone(self, limit=50):
        """Collect from HackerOne with visual feedback"""
        from src.collectors.hackerone_scraper import HackerOneScraper
        
        token = os.getenv("HACKERONE_TOKEN")
        if not token:
            console.print("[red]❌ HACKERONE_TOKEN not set[/red]")
            return
        
        scraper = HackerOneScraper(api_token=token)
        
        console.print(f"\n[bold green]🚀 Collecting from HackerOne (limit: {limit})...[/bold green]")
        
        # Create layout
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
        
        with Live(layout, refresh_per_second=4, console=console) as live:
            for report in scraper.fetch_reports_stream(limit=limit):
                # Add metadata
                report['source'] = 'HackerOne'
                report['time'] = datetime.now().strftime('%H:%M:%S')
                
                self.collected_reports.append(report)
                self.stats['hackerone'] += 1
                self.stats['total'] += 1
                
                # Update severity counts
                severity = report.get('severity', 'unknown').lower()
                if severity in self.stats:
                    self.stats[severity] += 1
                
                # Update layout
                layout["header"].update(self.create_header())
                layout["collection_stats"].update(self.create_stats_table())
                layout["severity"].update(self.create_severity_panel())
                layout["reports"].update(self.create_recent_reports_table())
                layout["current"].update(self.create_current_report_panel(report))
                
                time.sleep(0.05)  # Small delay for visual effect
        
        console.print(f"[bold green]✅ HackerOne collection complete![/bold green]")
    
    def save_results(self, output_dir='data/raw'):
        """Save collected reports"""
        Path(output_dir).mkdir(parents=True, exist_ok=True)
        
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        filename = f"{output_dir}/visual_collection_{timestamp}.json"
        
        with open(filename, 'w') as f:
            json.dump(self.collected_reports, f, indent=2)
        
        console.print(f"\n💾 [bold cyan]Saved {len(self.collected_reports)} reports to:[/bold cyan]")
        console.print(f"   {filename}")
        
        return filename

def main():
    """Main entry point"""
    import argparse
    
    parser = argparse.ArgumentParser(
        description='Visual data collection with Rich terminal UI'
    )
    parser.add_argument(
        '--source',
        choices=['hackerone', 'bugcrowd', 'cve', 'all'],
        default='hackerone',
        help='Data source (default: hackerone)'
    )
    parser.add_argument(
        '--limit',
        type=int,
        default=50,
        help='Number of reports to collect (default: 50)'
    )
    parser.add_argument(
        '--output',
        default='data/raw',
        help='Output directory (default: data/raw)'
    )
    
    args = parser.parse_args()
    
    # Show banner
    console.print()
    console.print(Panel.fit(
        "[bold white]🤖 BugPredict AI[/bold white]\n"
        "[cyan]Visual Data Collection System[/cyan]\n\n"
        f"Source: {args.source}\n"
        f"Limit: {args.limit} reports\n"
        f"Output: {args.output}",
        border_style="blue"
    ))
    console.print()
    
    # Create collector
    collector = VisualCollector()
    
    try:
        # Collect data
        if args.source in ['hackerone', 'all']:
            collector.collect_from_hackerone(limit=args.limit)
        
        # TODO: Add bugcrowd and cve collection here
        
        # Show summary
        console.print()
        console.print(Panel.fit(
            f"[bold green]✅ Collection Complete![/bold green]\n\n"
            f"Total Reports: [bold]{collector.stats['total']}[/bold]\n"
            f"HackerOne: {collector.stats['hackerone']}\n"
            f"Bugcrowd: {collector.stats['bugcrowd']}\n"
            f"CVE/NVD: {collector.stats['cve']}\n\n"
            f"Critical: [red]{collector.stats['critical']}[/red]\n"
            f"High: [yellow]{collector.stats['high']}[/yellow]\n"
            f"Medium: [blue]{collector.stats['medium']}[/blue]\n"
            f"Low: [green]{collector.stats['low']}[/green]",
            title="📊 Summary",
            border_style="green"
        ))
        
        # Save results
        output_file = collector.save_results(output_dir=args.output)
        
        console.print()
        console.print("[bold green]🎉 Done! Happy hunting![/bold green]")
        console.print()
        
    except KeyboardInterrupt:
        console.print("\n\n[yellow]⚠️  Collection interrupted by user[/yellow]")
        if collector.collected_reports:
            collector.save_results(output_dir=args.output)
    except Exception as e:
        console.print(f"\n[red]❌ Error: {e}[/red]")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
