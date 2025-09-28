#!/usr/bin/env python3
"""
VirusTotal Analysis Tool
A command-line tool to analyze files and URLs using VirusTotal API
"""

import argparse
import sys
import vt
from pathlib import Path
from tabulate import tabulate
from datetime import datetime
import json

# Import API key from config file
try:
    from config import VT_API_KEY
except ImportError:
    print("Error: Please create a config.py file with your VirusTotal API key")
    print("Example: VT_API_KEY = 'your-api-key-here'")
    sys.exit(1)


def parse_arguments():
    """Parse command-line arguments"""
    parser = argparse.ArgumentParser(
        description='VirusTotal Analysis Tool - Analyze files and URLs using VirusTotal API',
        formatter_class=argparse.RawDescriptionHelpFormatter
    )
    
    # Create a group for mutually exclusive required arguments
    input_group = parser.add_mutually_exclusive_group(required=True)
    
    input_group.add_argument(
        '-u', '--url',
        type=str,
        help='Single URL to analyze'
    )
    
    input_group.add_argument(
        '-f', '--file-hash',
        type=str,
        help='Single file hash to analyze (MD5, SHA1, or SHA256)'
    )
    
    input_group.add_argument(
        '-pF', '--file-hashes',
        type=str,
        help='Path to text file containing multiple file hashes (one per line)'
    )
    
    input_group.add_argument(
        '-pU', '--urls-file',
        type=str,
        help='Path to text file containing multiple URLs (one per line)'
    )
    
    parser.add_argument(
        '-o', '--output',
        type=str,
        help='Path to save output results'
    )
    
    return parser.parse_args()


def read_file_lines(filepath):
    """Read lines from a file and return as list"""
    try:
        with open(filepath, 'r') as f:
            lines = [line.strip() for line in f if line.strip()]
        return lines
    except FileNotFoundError:
        print(f"Error: File '{filepath}' not found")
        sys.exit(1)
    except Exception as e:
        print(f"Error reading file '{filepath}': {e}")
        sys.exit(1)


def analyze_file_hash(client, file_hash):
    """Analyze a single file hash"""
    try:
        file_obj = client.get_object(f"/files/{file_hash}")
        
        # Extract relevant information
        result = {
            'Type': 'File',
            'Hash/URL': file_hash[:50] + '...' if len(file_hash) > 50 else file_hash,
            'SHA256': file_obj.sha256[:16] + '...' if hasattr(file_obj, 'sha256') else 'N/A',
            'File Type': getattr(file_obj, 'type_tag', 'N/A'),
            'Size': f"{getattr(file_obj, 'size', 0):,} bytes",
            'Malicious': file_obj.last_analysis_stats.get('malicious', 0),
            'Suspicious': file_obj.last_analysis_stats.get('suspicious', 0),
            'Harmless': file_obj.last_analysis_stats.get('harmless', 0),
            'Undetected': file_obj.last_analysis_stats.get('undetected', 0),
            'Timeout': file_obj.last_analysis_stats.get('timeout', 0),
            'Detection Rate': f"{file_obj.last_analysis_stats.get('malicious', 0)}/{sum(file_obj.last_analysis_stats.values())}",
            'Status': 'MALICIOUS' if file_obj.last_analysis_stats.get('malicious', 0) > 0 else 'CLEAN'
        }
        
        # Add file names if available
        if hasattr(file_obj, 'names') and file_obj.names:
            result['File Names'] = ', '.join(file_obj.names[:3])
            if len(file_obj.names) > 3:
                result['File Names'] += f' (+{len(file_obj.names) - 3} more)'
        
        return result
        
    except vt.error.APIError as e:
        return {
            'Type': 'File',
            'Hash/URL': file_hash[:50] + '...' if len(file_hash) > 50 else file_hash,
            'Status': f'Error: {str(e)}'
        }


def analyze_url(client, url):
    """Analyze a single URL"""
    try:
        url_id = vt.url_id(url)
        url_obj = client.get_object(f"/urls/{url_id}")
        
        # Extract relevant information
        result = {
            'Type': 'URL',
            'Hash/URL': url[:50] + '...' if len(url) > 50 else url,
            'Times Submitted': f"{getattr(url_obj, 'times_submitted', 0):,}",
            'Malicious': url_obj.last_analysis_stats.get('malicious', 0),
            'Suspicious': url_obj.last_analysis_stats.get('suspicious', 0),
            'Harmless': url_obj.last_analysis_stats.get('harmless', 0),
            'Undetected': url_obj.last_analysis_stats.get('undetected', 0),
            'Timeout': url_obj.last_analysis_stats.get('timeout', 0),
            'Detection Rate': f"{url_obj.last_analysis_stats.get('malicious', 0)}/{sum(url_obj.last_analysis_stats.values())}",
            'Status': 'MALICIOUS' if url_obj.last_analysis_stats.get('malicious', 0) > 0 else 'CLEAN'
        }
        
        # Add title if available
        if hasattr(url_obj, 'title'):
            result['Page Title'] = url_obj.title[:50] + '...' if len(url_obj.title) > 50 else url_obj.title
        
        return result
        
    except vt.error.APIError as e:
        return {
            'Type': 'URL',
            'Hash/URL': url[:50] + '...' if len(url) > 50 else url,
            'Status': f'Error: {str(e)}'
        }


def format_results_table(results):
    """Format results as a nice table"""
    if not results:
        return "No results to display"
    
    # Prepare data for tabulation
    headers = []
    rows = []
    
    for result in results:
        if not headers:
            headers = list(result.keys())
        
        row = [result.get(key, 'N/A') for key in headers]
        rows.append(row)
    
    return tabulate(rows, headers=headers, tablefmt='grid', stralign='left')


def save_output(content, filepath):
    """Save output to a file"""
    try:
        with open(filepath, 'w') as f:
            f.write(f"VirusTotal Analysis Report\n")
            f.write(f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            f.write(content)
            f.write("\n")
        print(f"\nOutput saved to: {filepath}")
    except Exception as e:
        print(f"Error saving output to '{filepath}': {e}")


def main():
    """Main function"""
    args = parse_arguments()
    
    # Initialize VT client
    try:
        client = vt.Client(VT_API_KEY)
    except Exception as e:
        print(f"Error initializing VirusTotal client: {e}")
        sys.exit(1)
    
    results = []
    
    try:
        # Process single URL
        if args.url:
            print(f"Analyzing URL: {args.url}")
            result = analyze_url(client, args.url)
            results.append(result)
        
        # Process single file hash
        elif args.file_hash:
            print(f"Analyzing file hash: {args.file_hash}")
            result = analyze_file_hash(client, args.file_hash)
            results.append(result)
        
        # Process multiple file hashes
        elif args.file_hashes:
            hashes = read_file_lines(args.file_hashes)
            print(f"Analyzing {len(hashes)} file hashes...")
            for i, hash_value in enumerate(hashes, 1):
                print(f"  [{i}/{len(hashes)}] {hash_value}")
                result = analyze_file_hash(client, hash_value)
                results.append(result)
        
        # Process multiple URLs
        elif args.urls_file:
            urls = read_file_lines(args.urls_file)
            print(f"Analyzing {len(urls)} URLs...")
            for i, url in enumerate(urls, 1):
                print(f"  [{i}/{len(urls)}] {url}")
                result = analyze_url(client, url)
                results.append(result)
        
        # Format results
        print("\n" + "=" * 80)
        print("ANALYSIS RESULTS")
        print("=" * 80 + "\n")
        
        table_output = format_results_table(results)
        print(table_output)
        
        # Summary statistics
        if len(results) > 1:
            malicious_count = sum(1 for r in results if r.get('Status') == 'MALICIOUS')
            clean_count = sum(1 for r in results if r.get('Status') == 'CLEAN')
            error_count = sum(1 for r in results if 'Error' in r.get('Status', ''))
            
            print("\n" + "=" * 80)
            print("SUMMARY")
            print("=" * 80)
            print(f"Total Analyzed: {len(results)}")
            print(f"Malicious: {malicious_count}")
            print(f"Clean: {clean_count}")
            print(f"Errors: {error_count}")
        
        # Save output if specified
        if args.output:
            save_content = table_output
            if len(results) > 1:
                save_content += f"\n\n{'=' * 80}\nSUMMARY\n{'=' * 80}\n"
                save_content += f"Total Analyzed: {len(results)}\n"
                save_content += f"Malicious: {malicious_count}\n"
                save_content += f"Clean: {clean_count}\n"
                save_content += f"Errors: {error_count}\n"
            save_output(save_content, args.output)
    
    finally:
        # Always close the client
        client.close()
        print("\nAnalysis complete.")


if __name__ == "__main__":
    main()