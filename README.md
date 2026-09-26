# Digital Evidence Analyzer

A web-based forensic investigation tool for metadata extraction, steganography
detection, file integrity verification, and automated PDF forensic reporting.

Built as a final-year project, based on the paper *"Digital Evidence Analyzer:
A Web-Based Forensic Investigation Platform"* (Priya M L, Shivani V et al.,
Maharaja Institute of Technology, Mysore).

## Features

- **File upload** through a browser - no installation required
- **Cryptographic hashing** (MD5 + SHA256) for file integrity verification
- **True file-type detection** via binary signature analysis (catches files
  disguised with a fake extension)
- **Metadata/EXIF extraction** - camera make/model, timestamps, GPS
  coordinates (converted to plain latitude/longitude)
- **Steganography detection** for images, using:
  - LSB (Least Significant Bit) statistical analysis via a chi-square test
  - File-size anomaly detection
- **Automated PDF forensic report generation** - a professional, downloadable
  report summarizing all findings
- **Safe analysis environment** - uploaded files are never executed, only
  read; files are deleted from the server immediately after analysis

## Technology Stack

| Component | Library |
|---|---|
| Backend | Python Flask |
| Image metadata | Pillow (PIL) |
| File type detection | filetype |
| Hashing | hashlib (built-in) |
| PDF report generation | ReportLab |
| Frontend | HTML5, CSS3, vanilla JavaScript |

## Project Structure

```
digital-evidence-analyzer/
├── app.py              - Flask backend (all analysis logic)
├── templates/
│   └── index.html      - Upload page + results dashboard
├── static/
│   └── style.css        - Dark cybersecurity-themed styling
├── uploads/             - Temporary storage during analysis (auto-cleared)
└── reports/             - Generated PDF reports
```

## Setup & Running Locally

1. Install Python 3.10+ 
2. Install dependencies:
   ```
   pip install flask filetype Pillow reportlab
   ```
3. Run the app:
   ```
   python app.py
   ```
4. Open a browser to `http://localhost:5000`

## Security Measures

- UUID-based filenames prevent path traversal and filename collisions
- Maximum upload size enforced (20 MB) to prevent denial-of-service via
  large files
- A short blocklist of dangerous file extensions (.exe, .bat, .sh, etc.)
  is rejected outright before any processing
- File type is verified by reading actual binary content, not by trusting
  the filename extension
- Uploaded files are never executed or interpreted - only read by
  analysis libraries
- Uploaded files are deleted from the server immediately after analysis
  completes
- All analysis is wrapped in error handling so a corrupted or malformed
  file returns a clean error message instead of crashing the server

## Known Limitations

- **Steganography detection** targets LSB embedding only. More advanced
  techniques (DCT-domain/JPEG steganography, palette manipulation) are not
  covered.
- The **file-size anomaly check** is most meaningful for uncompressed/lossless
  formats (PNG, BMP). JPEG's lossy compression makes this check unreliable
  for that format, and is flagged as such in the results.
- The chi-square LSB test is most reliable when a large portion of an
  image's capacity has been used for hidden data; very small embedded
  payloads may not be statistically distinguishable from natural image
  noise.
- EXIF metadata extraction currently applies to image files only; PDF/
  document metadata extraction is a potential future enhancement.
- Single-server Flask deployment - not designed for high-concurrency
  production use (matches the base paper's own noted limitation).

## Future Work

- Extend steganography detection to cover DCT-domain (JPEG) techniques
- Add document/PDF metadata extraction
- Case management for grouping multiple file analyses under one investigation
- Containerized deployment (Docker) for scalability

## Authors

Developed as a final-year Computer Science and Engineering project.
Based on the reference paper by Priya M L and Shivani V, under the guidance
of Prof. Seema C K and Prof. Swathi S, Maharaja Institute of Technology,
Mysore, Karnataka, India.
