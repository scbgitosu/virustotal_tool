# VirusTotal Analysis Tool

A Python command-line tool for analyzing files and URLs using the VirusTotal API v3. This tool provides batch processing capabilities, formatted output, and comprehensive malware detection statistics.

## 🚀 Features

- **Single and Batch Analysis**: Analyze individual files/URLs or process multiple items from text files
- **Multiple Input Methods**: Support for URLs, file hashes (MD5/SHA1/SHA256), and bulk input files
- **Comprehensive Detection Stats**: Shows malicious, suspicious, harmless, and undetected counts
- **Formatted Output**: Clean, table-formatted results for easy reading
- **Export Capabilities**: Save analysis results to text files
- **Error Handling**: Robust error handling for API failures and invalid inputs
- **Summary Statistics**: Aggregate statistics when analyzing multiple items

## 📋 Prerequisites

- Python 3.6 or higher
- VirusTotal API key (free or premium)
- Internet connection

## 🔧 Installation

1. **Clone or download this repository:**
```bash
git clone https://github.com/yourusername/vt-analysis-tool.git
cd vt-analysis-tool
```

2. **Install required dependencies:**
```bash
pip install vt-py tabulate
```

Or using the requirements file:
```bash
pip install -r requirements.txt
```

3. **Configure your API key:**
   - Get your API key from [VirusTotal](https://www.virustotal.com/gui/my-apikey)
   - Edit `config.py` and replace `'your-virustotal-api-key-here'` with your actual API key

## 📁 Project Structure

```
vt-analysis-tool/
│
├── vt_tool.py          # Main script
├── config.py           # API key configuration
├── requirements.txt    # Python dependencies
├── README.md          # This file
│
├── examples/          # Example input files (optional)
│   ├── hashes.txt    # Sample file hashes
│   └── urls.txt      # Sample URLs
│
└── output/           # Output directory (optional)
    └── results.txt   # Sample output file
```

## 💻 Usage

### Basic Command Structure

```bash
python vt_tool.py [OPTIONS]
```

### Command-Line Arguments

| Argument | Description | Required |
|----------|-------------|----------|
| `-u, --url` | Single URL to analyze | One of these is required |
| `-f, --file-hash` | Single file hash to analyze (MD5/SHA1/SHA256) | |
| `-pF, --file-hashes` | Path to text file with multiple hashes | |
| `-pU, --urls-file` | Path to text file with multiple URLs | |
| `-o, --output` | Path to save output results | Optional |

### Examples

#### Analyze a single URL:
```bash
python vt_tool.py -u "http://example.com"
```

#### Analyze a single file hash:
```bash
python vt_tool.py -f "275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f"
```

#### Analyze multiple file hashes from a file:
```bash
python vt_tool.py -pF hashes.txt
```

#### Analyze multiple URLs from a file:
```bash
python vt_tool.py -pU urls.txt -o results/analysis_report.txt
```

### Input File Format

**For hash files (`hashes.txt`):**
```
275a021bbfb6489e54d471899f7db9d1663fc695ec2fe2a2c4538aabf651fd0f
1234567890abcdef1234567890abcdef12345678
abcdef1234567890abcdef1234567890abcdef12
```

**For URL files (`urls.txt`):**
```
http://example.com
https://google.com
https://suspicious-site.org
http://malware-test.com
```

## 📊 Output Format

### Single Item Analysis
```
================================================================================
ANALYSIS RESULTS
================================================================================

┌──────┬─────────────────┬──────────┬───────────┬──────────┬──────────┬────────────┬─────────┐
│ Type │ Hash/URL        │ File Type│ Size      │ Malicious│ Suspicious│ Detection │ Status  │
├──────┼─────────────────┼──────────┼───────────┼──────────┼───────────┼────────────┼─────────┤
│ File │ 275a021bbfb6... │ text     │ 68 bytes  │ 62       │ 0         │ 62/73      │ MALICIOUS│
└──────┴─────────────────┴──────────┴───────────┴──────────┴───────────┴────────────┴─────────┘
```

### Batch Analysis with Summary
```
================================================================================
ANALYSIS RESULTS
================================================================================

[Table with multiple entries...]

================================================================================
SUMMARY
================================================================================
Total Analyzed: 10
Malicious: 3
Clean: 6
Errors: 1
```

## 🔑 API Information

### Rate Limits

**Free API:**
- 4 requests per minute
- 500 requests per day
- 15.5K requests per month

**Premium API:**
- Higher rate limits available
- Contact VirusTotal for pricing

### API Key Security

- Never commit your API key to version control
- Consider using environment variables for production deployments
- Add `config.py` to `.gitignore` if using Git

## 🛠️ Advanced Configuration

### Using Environment Variables

Instead of hardcoding the API key in `config.py`, you can use environment variables:

```python
# config.py
import os
VT_API_KEY = os.environ.get('VT_API_KEY', 'your-default-key-here')
```

Then set the environment variable:
```bash
export VT_API_KEY="your-actual-api-key"
python vt_tool.py -u "http://example.com"
```

### Proxy Configuration

If you're behind a corporate proxy, configure the vt-py client:

```python
# Add to vt_tool.py after imports
import os
os.environ['HTTP_PROXY'] = 'http://proxy.company.com:8080'
os.environ['HTTPS_PROXY'] = 'http://proxy.company.com:8080'
```

## 🐛 Troubleshooting

### Common Issues and Solutions

1. **"Error: Please create a config.py file"**
   - Ensure `config.py` exists in the same directory as `vt_tool.py`
   - Check that the file contains the `VT_API_KEY` variable

2. **"Error: 401 Unauthorized"**
   - Verify your API key is correct
   - Check if your API key has been activated

3. **"Error: 404 Not Found"**
   - The hash/URL might not exist in VirusTotal's database
   - Try submitting the file/URL to VirusTotal first

4. **"Error: 204 Request rate limit exceeded"**
   - You've exceeded the API rate limits
   - Wait before making more requests or upgrade your API plan

5. **Module import errors**
   - Ensure all dependencies are installed: `pip install vt-py tabulate`
   - Check you're using Python 3.6+

## 📈 Performance Tips

- When analyzing multiple items, the tool processes them sequentially to respect rate limits
- For large batches, consider implementing delays between requests
- Use premium API keys for production workloads

## 🤝 Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

### Development Setup

1. Fork the repository
2. Create a feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the LICENSE file for details.

## 🙏 Acknowledgments

- [VirusTotal](https://www.virustotal.com/) for providing the API
- [vt-py](https://github.com/VirusTotal/vt-py) - Official VirusTotal Python client
- [tabulate](https://github.com/astanin/python-tabulate) - Python table formatting library

## 📮 Contact & Support

- Create an issue on GitHub for bug reports or feature requests
- Check VirusTotal's [API documentation](https://developers.virustotal.com/reference) for API-specific questions
- Visit VirusTotal's [support page](https://support.virustotal.com/) for account and API key issues

## 🔄 Version History

- **v1.0.0** (Initial Release)
  - Single and batch file/URL analysis
  - Formatted table output
  - Export functionality
  - Summary statistics

---

**Disclaimer:** This tool is for educational and legitimate security research purposes only. Always ensure you have proper authorization before analyzing files or URLs.
