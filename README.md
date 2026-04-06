# XSS Scanner

## Implemented
- Reflected XSS ✅

## Not implemented
- Stored XSS ❌
- DOM XSS ❌

## Description
This scanner is designed to detect **Reflected XSS** vulnerabilities. 
It automatically searches for input fields and checks whether the entered text is displayed on the page, which helps identify potential vulnerabilities. 

## Requirements
- Python 3.10+
- `argparse`, `urllib`, `playwright`

## Usage
```bash
1. Clone the repository:
git clone https://github.com/NexusFault/reflected-xss-scanner.git

2. Installing dependencies:
pip install -r requirements.txt

3. Launch the scanner:
python xss_scanner.py --url "https://example.com"
```

## Notes
- You can use other wordlists for XSS injection, like `PayloadAllThings`, for more extensive testing.
- Run `python xss_scanner.py --help` to see all supported arguments.