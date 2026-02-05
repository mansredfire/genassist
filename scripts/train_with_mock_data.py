#!/usr/bin/env python3
"""
Train models using mock data
Perfect for testing and development
"""

import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent))

import os
os.environ['PYTHONIOENCODING'] = 'utf-8'

from rich.console import Console
from rich.panel import Panel
import pickle

from test_with_mock_data import generate_mock_reports
from src.training.pipeline import TrainingPipeline

console = Console()

def main():
    """Train models with mock data"""
    
    import argparse
    
    parser = argparse.ArgumentParser(description='Train models with mock data')
    parser.add_argument('--reports', type=int, default=1000, 
                       help='Number of mock reports to generate (default: 1000)')
    parser.add_argument('--quick', action='store_true',
                       help='Quick training mode (ignored, kept for compatibility)')
    
    args = parser.parse_args()
    
    # Show banner
    console.print()
    console.print(Panel.fit(
        "[bold white]🤖 BugPredict AI[/bold white]\n"
        "[cyan]Model Training with Mock Data[/cyan]\n\n"
        f"Generating: {args.reports} reports",
        border_style="blue"
    ))
    console.print()
    
    # Generate mock data
    console.print("[bold green]Step 1: Generating mock vulnerability reports...[/bold green]\n")
    reports = generate_mock_reports(count=args.reports)
    
    console.print(f"[bold green]✅ Generated {len(reports)} reports[/bold green]\n")
    
    # Save mock data
    data_dir = Path('data') / 'raw'
    data_dir.mkdir(parents=True, exist_ok=True)
    
    mock_file = data_dir / 'mock_training_data.pkl'
    
    with open(mock_file, 'wb') as f:
        pickle.dump(reports, f)
    
    console.print(f"[cyan]💾 Saved mock data to: {mock_file}[/cyan]\n")
    
    # Training
    console.print("[bold green]Step 2: Training models...[/bold green]\n")
    console.print("[yellow]Note: Training may take 5-15 minutes[/yellow]\n")
    
    try:
        # Create pipeline
        pipeline = TrainingPipeline()
        
        # Load mock data
        pipeline.raw_reports = reports
        console.print(f"[cyan]→ Loaded {len(reports)} mock reports[/cyan]\n")
        
        # Preprocess
        console.print("[cyan]→ Preprocessing data...[/cyan]")
        pipeline.processed_reports = pipeline.preprocess_data()
        console.print(f"[green]✓ Preprocessed {len(pipeline.processed_reports)} reports[/green]\n")
        
        # Feature engineering
        console.print("[cyan]→ Engineering features...[/cyan]")
        pipeline.feature_data = pipeline.engineer_features()
        console.print(f"[green]✓ Features engineered[/green]\n")
        
        # Train models
        console.print("[cyan]→ Training vulnerability classifier...[/cyan]")
        pipeline.train_vulnerability_model()
        console.print("[green]✓ Vulnerability classifier trained[/green]\n")
        
        console.print("[cyan]→ Training severity predictor...[/cyan]")
        pipeline.train_severity_model()
        console.print("[green]✓ Severity predictor trained[/green]\n")
        
        console.print("[cyan]→ Training chain detector...[/cyan]")
        pipeline.train_chain_detector()
        console.print("[green]✓ Chain detector trained[/green]\n")
        
        # Save models
        console.print("[cyan]→ Saving models...[/cyan]")
        pipeline.save_models()
        console.print(f"[green]✓ Models saved to: data\\models[/green]\n")
        
        # Summary
        console.print()
        console.print(Panel.fit(
            "[bold green]✅ Training Complete![/bold green]\n\n"
            f"Reports Processed: {len(pipeline.processed_reports)}\n"
            "Models Trained: 3\n\n"
            "Models saved to: data\\models\\\n"
            "Ready for predictions!",
            title="📊 Summary",
            border_style="green"
        ))
        
        console.print("\n[bold cyan]Next steps:[/bold cyan]")
        console.print("  python scripts\\analyze_target.py --domain example.com\n")
        
    except Exception as e:
        console.print(f"\n[bold red]❌ Error:[/bold red]")
        console.print(f"[red]{e}[/red]\n")
        import traceback
        traceback.print_exc()
        return 1
    
    return 0

if __name__ == "__main__":
    sys.exit(main())
