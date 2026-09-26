"""
Digital Evidence Analyzer - Flask Backend
Phase 1: Just handles file upload. No forensics yet.

BEGINNER NOTES:
- Flask is a "micro web framework" - it's the minimum code needed to run a website.
- We define "routes" (URLs) and what Python function runs when someone visits them.
- "@app.route(...)" is a decorator - it connects a URL to a function below it.
"""

import os
import uuid
import hashlib
import filetype
from datetime import datetime
from PIL import Image
from PIL.ExifTags import TAGS, GPSTAGS
from flask import Flask, request, jsonify, render_template, send_from_directory
from reportlab.lib.pagesizes import A4
from reportlab.lib.units import cm
from reportlab.lib import colors
from reportlab.platypus import (
    SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, PageBreak
)
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle

# --- App setup ---
app = Flask(__name__)

# Folder where uploaded files will be temporarily stored
UPLOAD_FOLDER = os.path.join(os.path.dirname(__file__), "uploads")
app.config["UPLOAD_FOLDER"] = UPLOAD_FOLDER

# Folder where generated PDF reports will be saved
REPORTS_FOLDER = os.path.join(os.path.dirname(__file__), "reports")
app.config["REPORTS_FOLDER"] = REPORTS_FOLDER

# Limit uploads to 20 MB (prevents someone crashing our server with a huge file)
app.config["MAX_CONTENT_LENGTH"] = 20 * 1024 * 1024  # 20 MB in bytes


@app.route("/")
def home():
    """
    This runs when someone visits http://localhost:5000/
    It just shows the upload page (templates/index.html)
    """
    return render_template("index.html")


@app.route("/analyze", methods=["POST"])
def analyze():
    """
    This runs when the browser submits a file via POST to /analyze.
    Handles the full pipeline: upload -> hash -> detect type -> metadata ->
    steganography check -> PDF report -> cleanup.

    SECURITY NOTE: The entire pipeline is wrapped in try/except so that a
    corrupted, malformed, or unexpected file can never crash the server or
    leak a raw Python error page to the user - it just returns a clean
    JSON error message instead.
    """

    # Step 1: Check a file was actually sent
    if "file" not in request.files:
        return jsonify({"error": "No file part in the request"}), 400

    uploaded_file = request.files["file"]

    if uploaded_file.filename == "":
        return jsonify({"error": "No file selected"}), 400

    # Step 2: Generate a safe, unique filename
    # WHY: If two people upload "photo.jpg" at the same time, we don't want
    # them to overwrite each other's file. UUID = a random unique ID.
    original_filename = uploaded_file.filename
    file_extension = os.path.splitext(original_filename)[1].lower()  # e.g. ".jpg"

    # Basic extension sanity check - an extra, simple layer of defense.
    # NOTE: This is NOT our main security control. The real check is
    # detect_mime_type() below, which reads actual file content rather
    # than trusting a name that anyone could fake. This just blocks a
    # few obviously dangerous extensions outright before we even save.
    BLOCKED_EXTENSIONS = {".exe", ".bat", ".cmd", ".sh", ".msi", ".com", ".scr"}
    if file_extension in BLOCKED_EXTENSIONS:
        return jsonify({"error": f"File type '{file_extension}' is not allowed."}), 400

    safe_filename = f"{uuid.uuid4()}{file_extension}"
    save_path = os.path.join(app.config["UPLOAD_FOLDER"], safe_filename)

    try:
        # Step 3: Save the file to our uploads/ folder
        uploaded_file.save(save_path)
        file_size_bytes = os.path.getsize(save_path)

        # Step 4: Compute cryptographic hashes (MD5 + SHA256)
        md5_hash, sha256_hash = compute_hashes(save_path)

        # Step 5: Detect the TRUE file type by reading its binary content
        true_mime_type = detect_mime_type(save_path)

        # Step 6: Extract forensic metadata
        metadata = extract_metadata(save_path, original_filename, true_mime_type)

        # Step 7: Steganography detection (images only)
        steganography_result = None
        if true_mime_type and true_mime_type.startswith("image/"):
            steganography_result = detect_steganography(save_path, file_size_bytes)

        # Step 8: Generate a downloadable PDF forensic report
        analysis_results = {
            "original_filename": original_filename,
            "saved_as": safe_filename,
            "size_bytes": file_size_bytes,
            "true_mime_type": true_mime_type,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "metadata": metadata,
            "steganography": steganography_result
        }
        report_filename = generate_pdf_report(analysis_results)

        # Step 9: Confirm back to the browser (as JSON)
        return jsonify({
            "status": "success",
            "message": "File received and analyzed",
            "original_filename": original_filename,
            "saved_as": safe_filename,
            "size_bytes": file_size_bytes,
            "true_mime_type": true_mime_type,
            "md5": md5_hash,
            "sha256": sha256_hash,
            "metadata": metadata,
            "steganography": steganography_result,
            "report_filename": report_filename
        })

    except Exception as e:
        # Catch-all: something unexpected went wrong (corrupted file,
        # unreadable image, disk issue, etc.) - report it cleanly instead
        # of crashing.
        return jsonify({
            "error": "The file could not be analyzed. It may be corrupted, "
                     "empty, or in an unsupported format.",
            "details": str(e)
        }), 500

    finally:
        # Step 10: Clean up - delete the uploaded file after analysis.
        # WHY: The base paper's security model states files should not
        # persist between sessions. We've already extracted everything
        # we need (hashes, metadata, the PDF report), so there's no
        # reason to keep the original file sitting on the server.
        if os.path.exists(save_path):
            try:
                os.remove(save_path)
            except Exception:
                pass  # if cleanup fails, it's not critical enough to break the response


@app.route("/reports/<filename>")
def download_report(filename):
    """
    Serves a generated PDF report for download.
    WHY send_from_directory: Flask's safe way to serve files from a folder
    without exposing the rest of the server's filesystem.
    """
    return send_from_directory(app.config["REPORTS_FOLDER"], filename, as_attachment=True)


def compute_hashes(file_path):
    """
    Reads a file in small chunks (so we don't load huge files fully into memory)
    and computes MD5 and SHA256 hashes simultaneously.
    """
    md5 = hashlib.md5()
    sha256 = hashlib.sha256()

    with open(file_path, "rb") as f:  # "rb" = read binary mode
        # Read the file in 8KB chunks until there's nothing left
        for chunk in iter(lambda: f.read(8192), b""):
            md5.update(chunk)
            sha256.update(chunk)

    return md5.hexdigest(), sha256.hexdigest()


def detect_mime_type(file_path):
    """
    Uses the 'filetype' library to inspect the actual binary content
    (the file's "magic bytes" / signature) and determine its real type -
    independent of whatever extension the file was given.

    NOTE: filetype detects common binary formats (images, PDFs, archives,
    audio/video, etc.) by signature. Plain text files don't have a
    signature, so we handle that case separately.
    """
    try:
        kind = filetype.guess(file_path)
        if kind is None:
            return "unknown / could not detect (possibly a plain text file)"
        return kind.mime  # e.g. "image/jpeg", "application/pdf"
    except Exception as e:
        return f"Could not determine (error: {e})"


def extract_metadata(file_path, original_filename, mime_type):
    """
    Extracts forensic metadata from the file.
    - For images: EXIF data (camera info, GPS, timestamps) via Pillow
    - For everything else: basic filesystem-level info

    WHY separate paths: EXIF metadata only exists in image formats like
    JPEG/TIFF. PDFs, docs, etc. store metadata differently - that's a
    future enhancement, for now we report what we can.
    """
    metadata = {
        "file_type_detected": mime_type,
    }

    # Only attempt EXIF extraction if this is actually an image
    if mime_type and mime_type.startswith("image/"):
        exif_data = extract_exif(file_path)
        metadata.update(exif_data)
    else:
        metadata["note"] = "EXIF extraction only supported for image files in this version."

    return metadata


def extract_exif(image_path):
    """
    Opens an image with Pillow and reads its EXIF metadata block.
    Returns a clean dictionary of human-readable tag names -> values.
    """
    result = {}

    try:
        image = Image.open(image_path)

        # getexif() returns a dictionary-like object of numeric tag IDs -> values
        exif = image.getexif()

        if not exif or len(exif) == 0:
            result["exif_status"] = "No EXIF metadata found in this image."
            return result

        result["exif_status"] = "EXIF metadata found."

        # Convert numeric tag IDs into readable names (e.g. 271 -> "Make")
        readable_tags = {}

        for tag_id, value in exif.items():
            tag_name = TAGS.get(tag_id, tag_id)

            # GPSInfo (tag 34853) is just a pointer/offset here, not the
            # actual GPS data - we fetch the real GPS sub-block separately
            # below using get_ifd(), so we skip it in this loop.
            if tag_name == "GPSInfo":
                continue

            # Convert bytes to string where possible so it's JSON-friendly
            if isinstance(value, bytes):
                try:
                    value = value.decode(errors="replace")
                except Exception:
                    value = str(value)
            readable_tags[tag_name] = str(value)

        result["exif_tags"] = readable_tags

        # Fetch the GPS sub-block directly (GPS IFD tag = 0x8825 / 34853)
        gps_raw = exif.get_ifd(0x8825)
        gps_info = {}
        if gps_raw:
            for gps_tag_id, gps_value in gps_raw.items():
                gps_tag_name = GPSTAGS.get(gps_tag_id, gps_tag_id)
                gps_info[gps_tag_name] = gps_value

        # Convert raw GPS coordinates (degrees/minutes/seconds) into
        # simple decimal latitude/longitude if GPS data was present
        if gps_info:
            coords = convert_gps_to_decimal(gps_info)
            if coords:
                result["gps_coordinates"] = coords
            result["gps_raw"] = {k: str(v) for k, v in gps_info.items()}

        return result

    except Exception as e:
        return {"exif_status": f"Could not read EXIF data (error: {e})"}


def convert_gps_to_decimal(gps_info):
    """
    GPS coordinates in EXIF are stored as degrees/minutes/seconds plus a
    reference direction (N/S/E/W). This converts them into plain decimal
    latitude/longitude, e.g. 12.9716, 77.5946, which is what most maps expect.
    """
    try:
        def dms_to_decimal(dms, ref):
            degrees = float(dms[0])
            minutes = float(dms[1])
            seconds = float(dms[2])
            decimal = degrees + (minutes / 60.0) + (seconds / 3600.0)
            if ref in ["S", "W"]:
                decimal = -decimal
            return decimal

        if "GPSLatitude" in gps_info and "GPSLongitude" in gps_info:
            lat = dms_to_decimal(gps_info["GPSLatitude"], gps_info.get("GPSLatitudeRef", "N"))
            lon = dms_to_decimal(gps_info["GPSLongitude"], gps_info.get("GPSLongitudeRef", "E"))
            return {"latitude": lat, "longitude": lon}

    except Exception:
        pass

    return None


def detect_steganography(image_path, actual_file_size):
    """
    Runs two independent checks to estimate whether an image might contain
    hidden (steganographic) data:

    1. LSB Statistical Analysis (chi-square test):
       In a normal, unmodified photo, the *last bit* of each pixel's color
       value is essentially random - roughly 50% are 0, 50% are 1, due to
       natural image noise. If someone hides a message in these bits, the
       pattern becomes noticeably different from random. We measure "how
       different from random" using a chi-square statistical test.

    2. File Size Anomaly Check:
       We estimate what an "uncompressed" version of this image should
       weigh, based on its width/height, and compare it to the real file
       size. This is a rough heuristic and works best on formats like PNG
       or BMP - JPEG's heavy compression makes this check unreliable there.
    """
    result = {}

    try:
        image = Image.open(image_path)
        image_format = image.format  # e.g. "JPEG", "PNG"
        width, height = image.size

        # Ensure image has standard RGB channels to analyze
        rgb_image = image.convert("RGB")
        pixels = list(rgb_image.getdata())

        # --- Check 1: LSB Statistical Analysis ---
        lsb_result = analyze_lsb(pixels)
        result["lsb_analysis"] = lsb_result

        # --- Check 2: File Size Anomaly ---
        size_result = analyze_file_size_anomaly(width, height, actual_file_size, image_format)
        result["file_size_analysis"] = size_result

        # --- Combine into an overall verdict ---
        if lsb_result["suspicious"]:
            result["verdict"] = "Possible steganography detected (unusual LSB pattern)."
        else:
            result["verdict"] = "No strong indication of LSB steganography."

        return result

    except Exception as e:
        return {"error": f"Could not analyze image for steganography (error: {e})"}


def analyze_lsb(pixels):
    """
    Extracts the least significant bit (LSB) from every color channel
    (Red, Green, Blue) across all pixels, then runs a chi-square test
    to see if the distribution of 0s and 1s looks random (normal) or
    suspiciously patterned (possible hidden data).
    """
    zero_count = 0
    one_count = 0

    for pixel in pixels:
        r, g, b = pixel[0], pixel[1], pixel[2]
        for channel_value in (r, g, b):
            lsb = channel_value & 1  # extract just the last bit (0 or 1)
            if lsb == 0:
                zero_count += 1
            else:
                one_count += 1

    total = zero_count + one_count
    expected = total / 2  # in a random distribution, we'd expect 50/50

    # Chi-square statistic: measures how far observed counts are from expected
    chi_square = ((zero_count - expected) ** 2) / expected + \
                 ((one_count - expected) ** 2) / expected

    # NOTE ON THRESHOLD: A chi-square value close to 0 means the distribution
    # is very close to the expected 50/50 split (looks random/natural).
    # A high chi-square value means a significant deviation from random -
    # which can indicate hidden data. This threshold (10.83 corresponds
    # to a 99.9% confidence level with 1 degree of freedom) is a common
    # statistical cutoff point, but it's a heuristic, not a guarantee.
    THRESHOLD = 10.83
    is_suspicious = chi_square > THRESHOLD

    return {
        "zero_bits": zero_count,
        "one_bits": one_count,
        "chi_square_value": round(chi_square, 4),
        "threshold": THRESHOLD,
        "suspicious": is_suspicious
    }


def analyze_file_size_anomaly(width, height, actual_size, image_format):
    """
    Estimates the size an uncompressed version of this image "should" be
    (width x height x 3 bytes for RGB) and compares it to the real file size.

    LIMITATION (important to note in your report): this check is only
    meaningful for uncompressed/lossless formats like PNG or BMP. JPEG uses
    lossy compression, so its files are always much smaller than this raw
    estimate - that's normal for JPEG, not a sign of hidden data.
    """
    expected_uncompressed_size = width * height * 3  # 3 bytes per pixel (RGB)

    if expected_uncompressed_size == 0:
        return {"note": "Could not compute - invalid image dimensions."}

    ratio = actual_size / expected_uncompressed_size

    note = ""
    if image_format == "JPEG":
        note = ("This is a JPEG file - JPEG compression normally makes files "
                "much smaller than their raw pixel size, so this ratio is not "
                "a reliable steganography indicator for this format.")
    elif ratio > 1.05:
        note = ("File is larger than its expected uncompressed size - "
                "this can (but does not always) indicate extra hidden data appended to the file.")
    else:
        note = "File size looks within a normal range for this image."

    return {
        "expected_uncompressed_bytes": expected_uncompressed_size,
        "actual_bytes": actual_size,
        "size_ratio": round(ratio, 4),
        "note": note
    }


def generate_pdf_report(results):
    """
    Builds a professional forensic PDF report using ReportLab, summarizing
    all analysis results: file identity, hashes, metadata, and
    steganography findings.

    WHY ReportLab: it lets us build PDFs programmatically in Python - text,
    tables, styling - without needing a separate design tool.

    Returns just the filename (not full path) so the frontend can build
    a download link like /reports/<filename>
    """
    report_id = str(uuid.uuid4())[:8]
    report_filename = f"forensic_report_{report_id}.pdf"
    report_path = os.path.join(app.config["REPORTS_FOLDER"], report_filename)

    doc = SimpleDocTemplate(report_path, pagesize=A4,
                             topMargin=2*cm, bottomMargin=2*cm)
    styles = getSampleStyleSheet()

    # Custom style for our main title
    title_style = ParagraphStyle(
        "ReportTitle", parent=styles["Title"], fontSize=20, spaceAfter=6
    )
    section_style = ParagraphStyle(
        "SectionHeading", parent=styles["Heading2"],
        textColor=colors.HexColor("#1f4e79"), spaceBefore=16, spaceAfter=8
    )

    elements = []

    # --- Cover section ---
    elements.append(Paragraph("Digital Forensic Investigation Report", title_style))
    elements.append(Paragraph("Generated by Digital Evidence Analyzer", styles["Normal"]))
    elements.append(Spacer(1, 0.3*cm))
    generated_at = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    elements.append(Paragraph(f"Report generated on: {generated_at}", styles["Normal"]))
    elements.append(Paragraph(f"Report ID: {report_id}", styles["Normal"]))
    elements.append(Spacer(1, 0.6*cm))

    # --- File identification section ---
    elements.append(Paragraph("1. File Identification", section_style))
    file_table_data = [
        ["Original Filename", results["original_filename"]],
        ["Stored As", results["saved_as"]],
        ["File Size", f"{results['size_bytes']:,} bytes"],
        ["Detected True Type", results["true_mime_type"] or "Unknown"],
    ]
    elements.append(_build_table(file_table_data))

    # --- File integrity section ---
    elements.append(Paragraph("2. File Integrity (Cryptographic Hashes)", section_style))
    hash_table_data = [
        ["MD5", results["md5"]],
        ["SHA256", results["sha256"]],
    ]
    elements.append(_build_table(hash_table_data))

    # --- Metadata section ---
    elements.append(Paragraph("3. Metadata Analysis", section_style))
    metadata = results.get("metadata") or {}
    if metadata.get("exif_tags"):
        meta_rows = [[k, v] for k, v in metadata["exif_tags"].items()]
        elements.append(_build_table(meta_rows))
    else:
        status_text = metadata.get("exif_status") or metadata.get("note") or "No metadata available."
        elements.append(Paragraph(status_text, styles["Normal"]))

    if metadata.get("gps_coordinates"):
        lat = metadata["gps_coordinates"]["latitude"]
        lon = metadata["gps_coordinates"]["longitude"]
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(f"GPS Location Found: {lat:.6f}, {lon:.6f}", styles["Normal"]))

    # --- Steganography section ---
    steg = results.get("steganography")
    if steg and not steg.get("error"):
        elements.append(Paragraph("4. Steganography Analysis", section_style))
        elements.append(Paragraph(f"<b>Verdict:</b> {steg['verdict']}", styles["Normal"]))
        elements.append(Spacer(1, 0.2*cm))

        lsb = steg["lsb_analysis"]
        lsb_rows = [
            ["LSB Zero-bits", f"{lsb['zero_bits']:,}"],
            ["LSB One-bits", f"{lsb['one_bits']:,}"],
            ["Chi-square Value", str(lsb["chi_square_value"])],
            ["Detection Threshold", str(lsb["threshold"])],
        ]
        elements.append(_build_table(lsb_rows))

        size_check = steg["file_size_analysis"]
        elements.append(Spacer(1, 0.3*cm))
        elements.append(Paragraph(size_check["note"], styles["Normal"]))

    # --- Footer note ---
    elements.append(Spacer(1, 1*cm))
    elements.append(Paragraph(
        "This report was generated automatically by the Digital Evidence Analyzer "
        "for educational and preliminary investigative purposes. Findings should be "
        "verified with professional forensic tools before use in legal proceedings.",
        styles["Italic"]
    ))

    doc.build(elements)
    return report_filename


def _build_table(row_data):
    """
    Small helper to build a consistently styled two-column table
    (label + value) used throughout the PDF report.
    """
    table = Table(row_data, colWidths=[5*cm, 10*cm])
    table.setStyle(TableStyle([
        ("BACKGROUND", (0, 0), (0, -1), colors.HexColor("#e8eef7")),
        ("TEXTCOLOR", (0, 0), (-1, -1), colors.black),
        ("FONTSIZE", (0, 0), (-1, -1), 9),
        ("GRID", (0, 0), (-1, -1), 0.5, colors.HexColor("#c0c0c0")),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
        ("TOPPADDING", (0, 0), (-1, -1), 6),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
        ("LEFTPADDING", (0, 0), (-1, -1), 8),
    ]))
    return table


if __name__ == "__main__":
    # debug=True auto-reloads the server when you save code changes
    # Never use debug=True in a real production deployment - just for our dev work
    app.run(debug=True, port=5000)
