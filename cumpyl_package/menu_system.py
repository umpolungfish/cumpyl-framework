#!/usr/bin/env python3
"""
Interactive menu system for Cumpyl Framework
"""

import os
import subprocess
from typing import Optional, Dict, Any, List
from rich.console import Console
from rich.panel import Panel
from rich.table import Table
from rich.text import Text
from rich.prompt import Prompt, Confirm
from rich.columns import Columns
from rich.layout import Layout

try:
    from .config import ConfigManager
except ImportError:
    from config import ConfigManager


class CumpylMenu:
    """Interactive menu system for Cumpyl Framework"""
    
    def __init__(self, config: ConfigManager = None):
        """Initialize the menu system"""
        self.console = Console()
        self.config = config
        self.target_file = None
        
    def show_banner(self):
        """Display the Cumpyl banner"""
        banner_text = Text()
        banner_text.append("🔥 CUMPYL FRAMEWORK v0.3.0 🔥\n", style="bold red")
        banner_text.append("Advanced Binary Analysis & Rewriting Platform\n", style="bold cyan")
        banner_text.append("Interactive Menu System", style="bold yellow")
        
        banner_panel = Panel(
            banner_text,
            border_style="bright_blue",
            padding=(1, 2),
            title="🚀 Welcome",
            title_align="center"
        )
        
        self.console.print(banner_panel)
        self.console.print()
        
    def select_target_file(self) -> bool:
        """Select the target binary file"""
        self.console.print(Panel("🎯 Target File Selection", style="bold green"))
        
        # Scan for recent files in the current directory
        current_dir = os.getcwd()
        binary_files = []
        
        # Look for common binary extensions
        for root, dirs, files in os.walk(current_dir):
            for file in files:
                if file.lower().endswith(('.exe', '.dll', '.so', '.bin', '.elf')):
                    rel_path = os.path.relpath(os.path.join(root, file), current_dir)
                    if len(rel_path) < 80:  # Only show reasonable length paths
                        binary_files.append(rel_path)
                if len(binary_files) >= 20:  # Limit to 20 files
                    break
            if len(binary_files) >= 20:
                break
        
        if binary_files:
            self.console.print("📁 Found binary files in current directory:")
            
            table = Table(show_header=True, header_style="bold")
            table.add_column("Index", style="cyan", width=8)
            table.add_column("File Path", style="green")
            table.add_column("Size", style="yellow", width=12)
            
            for i, file_path in enumerate(binary_files[:15]):  # Show top 15
                try:
                    size = os.path.getsize(file_path)
                    if size > 1024*1024:
                        size_str = f"{size/(1024*1024):.1f} MB"
                    elif size > 1024:
                        size_str = f"{size/1024:.1f} KB"
                    else:
                        size_str = f"{size} bytes"
                except:
                    size_str = "Unknown"
                
                table.add_row(str(i), file_path, size_str)
            
            self.console.print(table)
            self.console.print()
            
            choice = Prompt.ask(
                "Select file by index, or enter custom path",
                default="0"
            )
            
            if choice.isdigit() and 0 <= int(choice) < len(binary_files):
                self.target_file = binary_files[int(choice)]
            else:
                self.target_file = choice
        else:
            self.target_file = Prompt.ask("Enter path to binary file")
        
        # Verify the file exists
        if not os.path.exists(self.target_file):
            self.console.print(f"[red]❌ File not found: {self.target_file}[/red]")
            return False
        
        self.console.print(f"[green]✅ Target selected: {self.target_file}[/green]")
        return True
        
    def show_main_menu(self) -> str:
        """Display the main menu"""
        menu_options = [
            ("1", "🔍 Quick Analysis", "Fast section analysis and obfuscation suggestions"),
            ("2", "🧪 Deep Analysis", "Comprehensive plugin-based analysis with reporting"),
            ("3", "🔧 Interactive Hex Viewer", "Explore binary with interactive hex dump"),
            ("4", "⚡ Batch Processing", "Process multiple files with automated workflows"),
            ("5", "🎯 Encoding Operations", "Obfuscate specific sections with various encodings"),
            ("6", "📊 Generate Reports", "Create detailed analysis reports in multiple formats"),
            ("7", "⚙️ Configuration", "View and modify framework settings"),
            ("8", "📁 Change Target", "Select a different binary file"),
            ("h", "❓ Help", "Show detailed help and examples"),
            ("q", "🚪 Quit", "Exit the menu system")
        ]
        
        self.console.print(Panel(f"🎯 Target: {self.target_file}", style="bold blue"))
        
        table = Table(show_header=False, box=None, padding=(0, 2))
        table.add_column("Option", style="bold cyan", width=8)
        table.add_column("Action", style="bold white", width=25)
        table.add_column("Description", style="dim")
        
        for option, action, description in menu_options:
            table.add_row(option, action, description)
        
        menu_panel = Panel(
            table,
            title="🚀 Main Menu",
            border_style="bright_green",
            padding=(1, 1)
        )
        
        self.console.print(menu_panel)
        
        return Prompt.ask(
            "\n[bold yellow]Select an option[/bold yellow]",
            choices=[opt[0] for opt in menu_options],
            default="1"
        )
        
    def quick_analysis_menu(self):
        """Quick analysis menu"""
        self.console.print(Panel("🔍 Quick Analysis Options", style="bold green"))
        
        options = [
            ("1", "Section Analysis Only", f"cumpyl {self.target_file} --analyze-sections"),
            ("2", "Obfuscation Suggestions", f"cumpyl {self.target_file} --suggest-obfuscation"),
            ("3", "Both Analysis + Suggestions", f"cumpyl {self.target_file} --analyze-sections --suggest-obfuscation"),
            ("4", "With Basic Hex View", f"cumpyl {self.target_file} --analyze-sections --suggest-obfuscation --hex-view"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select quick analysis option[/yellow]",
            choices=[opt[0] for opt in options],
            default="3"
        )
        
        if choice == "b":
            return
        
        # Execute the selected command
        cmd = options[int(choice) - 1][2]
        self.execute_command(cmd)
        
    def hex_viewer_menu(self):
        """Interactive hex viewer menu"""
        self.console.print(Panel("🔧 Interactive Hex Viewer Options", style="bold magenta"))
        
        options = [
            ("1", "Basic Hex View", f"cumpyl {self.target_file} --hex-view"),
            ("2", "Interactive Section Selection", f"cumpyl {self.target_file} --hex-view-interactive"),
            ("3", "Hex + Full Analysis", f"cumpyl {self.target_file} --hex-view --run-analysis --suggest-obfuscation"),
            ("4", "Custom Range (specify offset)", "Custom command builder"),
            ("5", "View Specific Section", "Custom section selector"),
            ("6", "Large File View (8KB)", f"cumpyl {self.target_file} --hex-view --hex-view-bytes 8192"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Command/Action", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select hex viewer option[/yellow]",
            choices=[opt[0] for opt in options],
            default="2"
        )
        
        if choice == "b":
            return
        elif choice == "4":
            # Custom range input
            offset = Prompt.ask("Enter starting offset (hex like 0x1000 or decimal)", default="0x0")
            bytes_count = Prompt.ask("Enter number of bytes to display", default="2048")
            analysis = Confirm.ask("Include analysis and suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --hex-view --hex-view-offset {offset} --hex-view-bytes {bytes_count}"
            if analysis:
                cmd += " --run-analysis --suggest-obfuscation"
            
            self.execute_command(cmd)
        elif choice == "5":
            # Section selector
            section = Prompt.ask("Enter section name (e.g., .text, .data, .rdata)", default=".text")
            analysis = Confirm.ask("Include analysis and suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --hex-view --hex-view-section {section}"
            if analysis:
                cmd += " --run-analysis --suggest-obfuscation"
            
            self.execute_command(cmd)
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def deep_analysis_menu(self):
        """Deep analysis menu"""
        self.console.print(Panel("🧪 Deep Analysis Options", style="bold blue"))
        
        options = [
            ("1", "Plugin Analysis Only", f"cumpyl {self.target_file} --run-analysis"),
            ("2", "Analysis + HTML Report", f"cumpyl {self.target_file} --run-analysis --report-format html --report-output analysis.html"),
            ("3", "Analysis + JSON Report", f"cumpyl {self.target_file} --run-analysis --report-format json --report-output analysis.json"),
            ("4", "Full Workflow + Hex View", f"cumpyl {self.target_file} --run-analysis --suggest-obfuscation --hex-view"),
            ("5", "Malware Analysis Profile", f"cumpyl {self.target_file} --profile malware_analysis --run-analysis"),
            ("6", "Forensics Profile", f"cumpyl {self.target_file} --profile forensics --run-analysis"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=35)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select deep analysis option[/yellow]",
            choices=[opt[0] for opt in options],
            default="4"
        )
        
        if choice == "b":
            return
        
        cmd = options[int(choice) - 1][2]
        self.execute_command(cmd)
    
    def batch_processing_menu(self):
        """Batch processing menu"""
        self.console.print(Panel("⚡ Batch Processing Options", style="bold yellow"))
        
        options = [
            ("1", "Process Directory", "Process all binaries in a directory"),
            ("2", "Pattern-based Processing", "Process files matching specific patterns"),
            ("3", "Multi-operation Batch", "Apply multiple operations to files"),
            ("4", "Custom Batch Job", "Build custom batch processing command"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Details", style="dim")
        
        for opt, desc, details in options:
            table.add_row(opt, desc, details)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select batch processing option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "1":
            directory = Prompt.ask("Enter directory path", default=".r4g3c4g3")
            operation = Prompt.ask("Select operation", choices=["analyze_sections", "plugin_analysis", "hex_view"], default="plugin_analysis")
            cmd = f"cumpyl --batch-directory {directory} --batch-operation {operation} --report-format json --report-output batch_results.json"
            self.execute_command(cmd)
        elif choice == "4":
            self.console.print("[green]Building custom batch command...[/green]")
            directory = Prompt.ask("Directory path", default=".")
            extensions = Prompt.ask("File extensions (comma-separated)", default=".exe,.dll")
            operations = Prompt.ask("Operations (comma-separated)", default="plugin_analysis")
            workers = Prompt.ask("Max workers", default="4")
            
            cmd = f"cumpyl --batch-directory {directory} --batch-extensions {extensions} --batch-operation {operations} --max-workers {workers}"
            self.execute_command(cmd)
        else:
            self.console.print("[yellow]Feature coming soon![/yellow]")
            Prompt.ask("Press Enter to continue", default="")
    
    def encoding_operations_menu(self):
        """Encoding operations menu"""
        self.console.print(Panel("🎯 Encoding Operations", style="bold red"))
        
        options = [
            ("1", "Encode Single Section", f"cumpyl {self.target_file} --encode-section .text --encoding base64 -o encoded.exe"),
            ("2", "Encode Multiple Sections", f"cumpyl {self.target_file} --encode-section .text --encode-section .data --encoding hex"),
            ("3", "Custom Range Encoding", "Encode specific byte ranges with custom parameters"),
            ("4", "Batch Section Encoding", "Encode sections across multiple files"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=30)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select encoding option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "3":
            section = Prompt.ask("Section name", default=".text")
            offset = Prompt.ask("Start offset", default="0")
            length = Prompt.ask("Length (bytes)", default="256")
            encoding = Prompt.ask("Encoding type", choices=["hex", "base64", "compressed_base64"], default="base64")
            output = Prompt.ask("Output file", default="encoded.exe")
            
            cmd = f"cumpyl {self.target_file} --encode-section {section} --encode-offset {offset} --encode-length {length} --encoding {encoding} -o {output}"
            self.execute_command(cmd)
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def report_generation_menu(self):
        """Report generation menu"""
        self.console.print(Panel("📊 Report Generation Options", style="bold green"))
        
        options = [
            ("1", "HTML Report", f"cumpyl {self.target_file} --run-analysis --report-format html --report-output analysis.html"),
            ("2", "JSON Report", f"cumpyl {self.target_file} --run-analysis --report-format json --report-output analysis.json"),
            ("3", "YAML Report", f"cumpyl {self.target_file} --run-analysis --report-format yaml --report-output analysis.yaml"),
            ("4", "XML Report", f"cumpyl {self.target_file} --run-analysis --report-format xml --report-output analysis.xml"),
            ("5", "Custom Report", "Generate custom report with specific options"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=25)
        table.add_column("Command Preview", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select report format[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "5":
            format_choice = Prompt.ask("Report format", choices=["html", "json", "yaml", "xml"], default="html")
            output_file = Prompt.ask("Output filename", default=f"custom_report.{format_choice}")
            include_hex = Confirm.ask("Include hex view?", default=True)
            include_suggestions = Confirm.ask("Include obfuscation suggestions?", default=True)
            
            cmd = f"cumpyl {self.target_file} --run-analysis --report-format {format_choice} --report-output {output_file}"
            if include_hex:
                cmd += " --hex-view"
            if include_suggestions:
                cmd += " --suggest-obfuscation"
            
            self.execute_command(cmd)
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def configuration_menu(self):
        """Configuration menu"""
        self.console.print(Panel("⚙️ Configuration Options", style="bold magenta"))
        
        options = [
            ("1", "Show Current Config", "cumpyl --show-config"),
            ("2", "Validate Config", "cumpyl --validate-config"),
            ("3", "List Available Profiles", "View predefined analysis profiles"),
            ("4", "Plugin Information", "cumpyl --list-plugins"),
            ("b", "Back to Main Menu", "")
        ]
        
        table = Table(show_header=True, header_style="bold")
        table.add_column("Option", style="cyan", width=8)
        table.add_column("Description", style="white", width=25)
        table.add_column("Command", style="dim")
        
        for opt, desc, cmd in options:
            table.add_row(opt, desc, cmd)
        
        self.console.print(table)
        
        choice = Prompt.ask(
            "\n[yellow]Select configuration option[/yellow]",
            choices=[opt[0] for opt in options],
            default="1"
        )
        
        if choice == "b":
            return
        elif choice == "3":
            self.console.print("\n[bold cyan]Available Analysis Profiles:[/bold cyan]")
            profiles = [
                ("malware_analysis", "Advanced malware detection and analysis"),
                ("forensics", "Digital forensics and evidence collection"),
                ("research", "Academic research and reverse engineering")
            ]
            
            profile_table = Table(show_header=True, header_style="bold")
            profile_table.add_column("Profile", style="green")
            profile_table.add_column("Description", style="white")
            
            for profile, desc in profiles:
                profile_table.add_row(profile, desc)
            
            self.console.print(profile_table)
            self.console.print("\n[dim]Use --profile <name> to apply a profile[/dim]")
            Prompt.ask("Press Enter to continue", default="")
        else:
            cmd = options[int(choice) - 1][2]
            self.execute_command(cmd)
    
    def execute_command(self, command: str):
        """Execute a Cumpyl command"""
        self.console.print(f"\n[bold green]🚀 Executing:[/bold green] [cyan]{command}[/cyan]")
        self.console.print("─" * 80)
        
        try:
            # Run the command in the same Python environment
            result = subprocess.run(
                ["python", "-m", "cumpyl_package.cumpyl"] + command.split()[1:],
                capture_output=False,
                text=True
            )
            
            self.console.print("─" * 80)
            if result.returncode == 0:
                self.console.print("[bold green]✅ Command completed successfully![/bold green]")
            else:
                self.console.print(f"[bold red]❌ Command failed with return code: {result.returncode}[/bold red]")
                
        except Exception as e:
            self.console.print(f"[bold red]❌ Error executing command: {e}[/bold red]")
        
        self.console.print()
        Prompt.ask("Press Enter to continue", default="")
    
    def show_help(self):
        """Display help information"""
        help_text = """
🔥 **CUMPYL FRAMEWORK** - Advanced Binary Analysis & Rewriting Platform

**🎯 Quick Start Guide:**
1. Use menu option 1 for fast analysis and obfuscation suggestions
2. Use menu option 3 for interactive hex exploration with visual tooltips
3. Use menu option 2 for comprehensive analysis with detailed reports

**🔧 Key Features:**
• **Interactive Hex Viewer**: Hover over bytes for detailed analysis tooltips
• **Section Analysis**: Automatic classification and safety assessment
• **Plugin System**: Entropy analysis, string extraction, and more
• **Batch Processing**: Analyze multiple files simultaneously
• **Multiple Report Formats**: HTML, JSON, YAML, XML output options

**🎨 Hex Viewer Highlights:**
• Color-coded annotations by type and severity
• Interactive section selection with tabular overview
• Custom range specification with hex notation support
• Real-time annotation counting and display
• Working hover tooltips with detailed information

**📊 Analysis Capabilities:**
• Shannon entropy calculation for packed binary detection
• Advanced string extraction with context scoring
• Section-by-section safety assessment for obfuscation
• Multi-tier recommendation system (Advanced/Intermediate/Basic/Avoid)

**⚡ Command Examples:**
• Quick analysis: `cumpyl binary.exe --analyze-sections --suggest-obfuscation`
• Interactive hex: `cumpyl binary.exe --hex-view-interactive`
• Full workflow: `cumpyl binary.exe --hex-view --run-analysis --suggest-obfuscation`
• Custom range: `cumpyl binary.exe --hex-view --hex-view-offset 0x1000 --hex-view-bytes 2048`

**📁 File Support:**
• PE files (.exe, .dll)
• ELF files (.so, .bin)
• Mach-O files
• Raw binary files

For detailed documentation, check the CLAUDE.md file in the project directory.
        """
        
        help_panel = Panel(
            help_text.strip(),
            title="📚 Cumpyl Framework Help",
            border_style="bright_yellow",
            padding=(1, 2)
        )
        
        self.console.print(help_panel)
        Prompt.ask("\nPress Enter to continue", default="")
    
    def run(self):
        """Run the interactive menu loop"""
        self.show_banner()
        
        # If no target file is set, select one
        if not self.target_file:
            if not self.select_target_file():
                return
        
        while True:
            try:
                choice = self.show_main_menu()
                
                if choice == "q":
                    self.console.print("[bold green]👋 Thank you for using Cumpyl Framework![/bold green]")
                    break
                elif choice == "1":
                    self.quick_analysis_menu()
                elif choice == "2":
                    self.deep_analysis_menu()
                elif choice == "3":
                    self.hex_viewer_menu()
                elif choice == "4":
                    self.batch_processing_menu()
                elif choice == "5":
                    self.encoding_operations_menu()
                elif choice == "6":
                    self.report_generation_menu()
                elif choice == "7":
                    self.configuration_menu()
                elif choice == "8":
                    self.select_target_file()
                elif choice == "h":
                    self.show_help()
                    
            except KeyboardInterrupt:
                self.console.print("\n[bold yellow]💡 Use 'q' to quit gracefully[/bold yellow]")
            except Exception as e:
                self.console.print(f"[bold red]❌ Menu error: {e}[/bold red]")
                Prompt.ask("Press Enter to continue", default="")


def launch_menu(config: ConfigManager = None, target_file: str = None):
    """Launch the interactive menu"""
    menu = CumpylMenu(config)
    if target_file:
        menu.target_file = target_file
    menu.run()


if __name__ == "__main__":
    launch_menu()