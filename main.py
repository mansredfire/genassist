# src/cli/main.py

import click
import json
from pathlib import Path
from rich.console import Console
from rich.table import Table
from rich.progress import Progress
from src.inference.predictor import ThreatPredictor
from src.collectors.tech_detector import TechnologyDetector

console = Console()

@click.group()
def cli():
    """BugPredict AI - ML-Powered Vulnerability Prediction Tool"""
    pass

@cli.command()
@click.option('--domain', '-d', required=True, help='Target domain')
@click.option('--output', '-o', default='report.json', help='Output file')
@click.option('--format', '-f', type=click.Choice(['json', 'text', 'html']), 
              default='json', help='Output format')
@click.option('--verbose', '-v', is_flag=True, help='Verbose output')
def analyze(domain, output, format, verbose):
    """Analyze a target and predict vulnerabilities"""
    
    console.print(f"\n[bold cyan]🎯 BugPredict AI - Analyzing {domain}[/bold cyan]\n")
    
    with Progress() as progress:
        # Detect technology stack
        task1 = progress.add_task("[cyan]Detecting technology stack...", total=100)
        tech_detector = TechnologyDetector()
        tech_info = tech_detector.detect(domain)
        progress.update(task1, advance=100)
        
        # Load predictor
        task2 = progress.add_task("[cyan]Loading ML models...", total=100)
        predictor = ThreatPredictor()
        progress.update(task2, advance=100)
        
        # Prepare target info
        target_info = {
            'domain': domain,
            'company_name': domain.split('.')[0],
            'technology_stack': tech_info['technologies'],
            'endpoints': tech_info.get('endpoints', ['/']),
            'auth_required': tech_info.get('has_auth', False)
        }
        
        # Analyze
        task3 = progress.add_task("[cyan]Analyzing and predicting...", total=100)
        results = predictor.analyze_target(target_info)
        progress.update(task3, advance=100)
    
    # Display results
    _display_results(results, format, output, verbose)
    
    console.print(f"\n[bold green]✅ Analysis complete! Results saved to {output}[/bold green]\n")

def _display_results(results, format_type, output_file, verbose):
    """Display analysis results"""
    
    if format_type == 'json':
        with open(output_file, 'w') as f:
            json.dump(results, f, indent=2)
    
    # Console output
    console.print("\n[bold]📊 Vulnerability Predictions[/bold]\n")
    
    # Create table
    table = Table(show_header=True, header_style="bold magenta")
    table.add_column("Rank", style="dim", width=6)
    table.add_column("Vulnerability")
    table.add_column("Probability", justify="right")
    table.add_column("Confidence")
    table.add_column("Priority", justify="center")
    
    for idx, vuln in enumerate(results['vulnerability_predictions'][:10], 1):
        priority_stars = "⭐" * vuln['priority']
        table.add_row(
            str(idx),
            vuln['vulnerability_type'],
            f"{vuln['probability']:.1%}",
            vuln['confidence'],
            priority_stars
        )
    
    console.print(table)
    
    # Risk score
    risk_score = results['risk_score']
    risk_color = "red" if risk_score > 7 else "yellow" if risk_score > 4 else "green"
    console.print(f"\n[bold]Overall Risk Score: [{risk_color}]{risk_score}/10[/{risk_color}][/bold]\n")
    
    # Chains
    if results['chain_predictions']:
        console.print("\n[bold]⛓️  Potential Vulnerability Chains[/bold]\n")
        for chain in results['chain_predictions']:
            console.print(f"  • {chain['name']}")
            console.print(f"    Vulnerabilities: {' → '.join(chain['vulns'])}")
            console.print(f"    Severity: {chain['severity']}\n")
    
    # Recommendations
    console.print("\n[bold]💡 Recommendations[/bold]\n")
    for rec in results['recommendations']:
        console.print(f"  • {rec}")

@cli.command()
@click.option('--target', '-t', required=True, help='Target domain or file')
@click.option('--output-dir', '-o', default='nuclei-templates/custom', 
              help='Output directory for templates')
def generate_templates(target, output_dir):
    """Generate Nuclei templates based on predictions"""
    
    from src.inference.predictor import NucleiTemplateGenerator
    
    console.print(f"\n[bold cyan]📝 Generating Nuclei Templates for {target}[/bold cyan]\n")
    
    # Analyze target first
    predictor = ThreatPredictor()
    target_info = {'domain': target, 'technology_stack': []}
    results = predictor.analyze_target(target_info)
    
    # Generate templates
    generator = NucleiTemplateGenerator()
    
    generated = []
    for vuln in results['vulnerability_predictions'][:5]:  # Top 5
        if vuln['probability'] > 0.5:
            template_path = generator.generate_template(
                vuln['vulnerability_type'], 
                target_info
            )
            generated.append(template_path)
            console.print(f"  ✅ Generated: {template_path}")
    
    console.print(f"\n[bold green]Generated {len(generated)} templates in {output_dir}[/bold green]\n")

@cli.command()
@click.option('--config', '-c', default='config/training_config.yaml', 
              help='Training configuration file')
def train(config):
    """Train the ML models"""
    
    from src.training.pipeline import TrainingPipeline
    
    console.print("\n[bold cyan]🚀 Starting Training Pipeline[/bold cyan]\n")
    
    pipeline = TrainingPipeline(config_path=config)
    pipeline.run_full_pipeline()
    
    console.print("\n[bold green]✅ Training completed![/bold green]\n")

@cli.command()
@click.option('--input', '-i', required=True, help='Input file with targets (one per line)')
@click.option('--output', '-o', default='batch_results.json', help='Output file')
@click.option('--threads', '-t', default=5, help='Number of concurrent threads')
def batch(input, output, threads):
    """Batch analyze multiple targets"""
    
    import concurrent.futures
    
    # Read targets
    with open(input, 'r') as f:
        targets = [line.strip() for line in f if line.strip()]
    
    console.print(f"\n[bold cyan]📦 Batch analyzing {len(targets)} targets[/bold cyan]\n")
    
    predictor = ThreatPredictor()
    results = []
    
    def analyze_single(domain):
        target_info = {'domain': domain, 'technology_stack': []}
        return predictor.analyze_target(target_info)
    
    with concurrent.futures.ThreadPoolExecutor(max_workers=threads) as executor:
        futures = {executor.submit(analyze_single, target): target for target in targets}
        
        with Progress() as progress:
            task = progress.add_task("[cyan]Analyzing...", total=len(targets))
            
            for future in concurrent.futures.as_completed(futures):
                target = futures[future]
                try:
                    result = future.result()
                    results.append(result)
                    console.print(f"  ✅ {target}")
                except Exception as e:
                    console.print(f"  ❌ {target}: {str(e)}")
                
                progress.update(task, advance=1)
    
    # Save results
    with open(output, 'w') as f:
        json.dump(results, f, indent=2)
    
    console.print(f"\n[bold green]✅ Batch analysis complete! Results saved to {output}[/bold green]\n")

if __name__ == '__main__':
    cli()
