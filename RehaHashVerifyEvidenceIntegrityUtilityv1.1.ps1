<#
RehaHashVerify - Evidence Integrity Utility (Modern UI)
Compatible: Windows PowerShell 5.1 + PowerShell 7 (Windows)

This version includes:
- Modern Status Button
- Error if MD5 and/or SHA256 value is incorrect 
- Added path and open folder buttons
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

# ---------------- App identity ----------------
$AppName    = "RehaHashVerify - Evidence Integrity Utility"
$AppVersion = "1.1"
$BuildDate  = "2026-02-11"
$AppOwner   = "Curtis Reha"
$BuildStamp = "v$AppVersion ($BuildDate)"

# ---------------- Helpers ----------------
function Normalize-InputPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }

    $p = ([string]$Path).Trim().Trim('"')

    if ($p.StartsWith("<") -and $p.EndsWith(">")) {
        $p = $p.Substring(1, $p.Length - 2).Trim()
    }

    # Convert file:/// URIs
    if ($p -match '^\s*file:/{2,3}') {
        try {
            $u = [Uri]$p
            if ($u -and $u.IsFile) { $p = $u.LocalPath }
        } catch {}
    }

    # Remove control/format/non-printing chars
    $p = [regex]::Replace($p, '\p{C}', '')

    return $p.Trim()
}

function Get-IllegalPathCharsReport {
    param([string]$p)

    if ([string]::IsNullOrWhiteSpace($p)) { return "Path is empty." }

    $bad = @()
    $invalid = [System.IO.Path]::GetInvalidPathChars()

    foreach ($ch in $p.ToCharArray()) {
        $code = [int][char]$ch
        if ($ch -match '\p{C}') {
            $bad += ("U+{0:X4} (Unicode category C)" -f $code)
            continue
        }
        if ($invalid -contains $ch) {
            $bad += ("U+{0:X4} (InvalidPathChar '{1}')" -f $code, $ch)
        }
    }

    if ($bad.Count -eq 0) { return "No illegal chars detected." }
    return "Illegal/invisible characters found:`r`n" + ($bad -join "`r`n")
}

# --- Expected hash validation (NO binding errors on empty string) ---
function Test-ExpectedHash {
    param(
        [AllowNull()]
        [AllowEmptyString()]
        [string]$Value,

        [Parameter(Mandatory=$true)]
        [ValidateSet('SHA256','MD5')]
        [string]$Alg,

        [Parameter(Mandatory=$true)]
        [string]$LabelForError
    )

    $v = ""
    if ($null -ne $Value) { $v = [string]$Value }

    $v = ($v -replace '\s','').Trim()

    # Blank allowed => "no expected hash provided"
    if ([string]::IsNullOrWhiteSpace($v)) {
        return @{ Ok = $true; Normalized = "" }
    }

    $expectedLen = if ($Alg -eq 'SHA256') { 64 } else { 32 }

    if ($v.Length -ne $expectedLen) {
        return @{
            Ok = $false
            Normalized = $v.ToUpperInvariant()
            Error = ("Invalid {0} input for {1}. Expected {2} hex characters, got {3}." -f $Alg, $LabelForError, $expectedLen, $v.Length)
        }
    }

    if ($v -notmatch '^[0-9a-fA-F]+$') {
        return @{
            Ok = $false
            Normalized = $v.ToUpperInvariant()
            Error = ("Invalid {0} input for {1}. Only hex characters allowed (0-9, A-F)." -f $Alg, $LabelForError)
        }
    }

    return @{ Ok = $true; Normalized = $v.ToUpperInvariant() }
}

function Build-DefaultReportPath {
    param(
        [Parameter(Mandatory=$true)][string]$BaseDir,
        [string]$CaseNumber,
        [string]$ItemNumber
    )
    $ts  = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $caseTag = ""
    if ($CaseNumber) { $caseTag += "_CASE-$($CaseNumber.Trim())" }
    if ($ItemNumber) { $caseTag += "_ITEM-$($ItemNumber.Trim())" }
    Join-Path $BaseDir ("RehaHashVerify{0}_{1}.txt" -f $caseTag, $ts)
}

function Convert-DictToHashtable($dict) {
    if (-not $dict) { return $null }
    $ht = @{}
    foreach ($k in $dict.Keys) { $ht[$k] = $dict[$k] }
    return $ht
}

function Write-CombinedReport {
    param(
        [Parameter(Mandatory=$true)][string]$ReportPath,
        [Parameter(Mandatory=$true)][hashtable]$Meta,
        [hashtable]$ZipSection,
        [hashtable]$KeychainSection
    )

    $lines = New-Object System.Collections.Generic.List[string]
    $lines.Add(("=" * 78))
    $lines.Add($AppName)
    $lines.Add("Tool Version: $BuildStamp")
    $lines.Add("Purpose: Independent hash verification of delivered evidence files.")
    $lines.Add("Generated: {0}" -f $Meta.GeneratedLocal)
    $lines.Add(("=" * 78))

    if ($Meta.CaseNumber) { $lines.Add("Case #:    {0}" -f $Meta.CaseNumber) }
    if ($Meta.ItemNumber) { $lines.Add("Item #:    {0}" -f $Meta.ItemNumber) }
    if ($Meta.Examiner)   { $lines.Add("Examiner:  {0}" -f $Meta.Examiner) }

    $lines.Add(("=" * 78))
    $lines.Add("")

    function Get-SecVal {
        param([object]$sec, [string]$key)
        if ($null -eq $sec) { return "" }
        if ($sec -is [System.Collections.IDictionary] -and $sec.Contains($key)) { return [string]$sec[$key] }
        return ""
    }

    function Add-FileSection([string]$Title, [hashtable]$S) {
        if (-not $S) { return }
        $lines.Add($Title)
        $lines.Add(("-" * 78))
        $lines.Add("Target File: {0}" -f (Get-SecVal $S 'FilePath'))
        $lines.Add("File Size : {0} bytes" -f (Get-SecVal $S 'SizeBytes'))
        $lines.Add("")
        $lines.Add("SHA-256")
        $lines.Add("  Expected: {0}" -f (Get-SecVal $S 'SHA256_Expected'))
        $lines.Add("  Actual  : {0}" -f (Get-SecVal $S 'SHA256_Actual'))
        $lines.Add("  Result  : {0}" -f (Get-SecVal $S 'SHA256_Result'))
        $lines.Add("")
        $lines.Add("MD5")
        $lines.Add("  Expected: {0}" -f (Get-SecVal $S 'MD5_Expected'))
        $lines.Add("  Actual  : {0}" -f (Get-SecVal $S 'MD5_Actual'))
        $lines.Add("  Result  : {0}" -f (Get-SecVal $S 'MD5_Result'))
        $lines.Add("")
        $lines.Add("File Result: {0}" -f (Get-SecVal $S 'FileOverall'))
        $lines.Add("")
    }

    if ($ZipSection)      { Add-FileSection 'ZIP FILE'      $ZipSection }
    if ($KeychainSection) { Add-FileSection 'KEYCHAIN FILE' $KeychainSection }

    $lines.Add(('=' * 78))
    $lines.Add(('OVERALL RESULT: {0}' -f $Meta.OverallResult))
    $lines.Add(('=' * 78))
    $lines.Add("")
    $lines.Add(("=" * 78))
    $lines.Add("Generated by $AppName ($BuildStamp). Owner: $AppOwner")
    $lines.Add(("=" * 78))

    $outDir = Split-Path -Parent $ReportPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }

    [System.IO.File]::WriteAllLines($ReportPath, $lines.ToArray(), [System.Text.Encoding]::UTF8)
}

# ---------------- Drag/drop routing ----------------
function Apply-DroppedFiles {
    param(
        [Parameter(Mandatory=$true)][string[]]$Files,
        [Parameter(Mandatory=$true)][object]$DroppedOnBox,
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$ZipBox,
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$KcBox
    )

    foreach ($f in $Files) {
        $p = Normalize-InputPath -Path ([string]$f)
        if ([string]::IsNullOrWhiteSpace($p)) { continue }

        $lower = $p.ToLowerInvariant()

        if ($lower -match '\.zip$') { $ZipBox.Text = $p; continue }

        if ($lower -match '\.(keychain|keychain-db|kc|db|sqlite|sqlite3|plist)$' -or
            ([System.IO.Path]::GetFileName($p).ToLowerInvariant().Contains("keychain"))) {
            $KcBox.Text = $p; continue
        }

        if ($DroppedOnBox -is [System.Windows.Forms.TextBox]) { $DroppedOnBox.Text = $p } else { $ZipBox.Text = $p }
    }
}

function Enable-DropToBox {
    param(
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$Box,
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$ZipBox,
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$KcBox
    )

    $Box.AllowDrop = $true

    $Box.Add_DragEnter({
        param($sender, $e)
        if ($e.Data.GetDataPresent([System.Windows.Forms.DataFormats]::FileDrop)) {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::Copy
        } else {
            $e.Effect = [System.Windows.Forms.DragDropEffects]::None
        }
    }.GetNewClosure())

    $Box.Add_DragDrop({
        param($sender, $e)
        $files = $e.Data.GetData([System.Windows.Forms.DataFormats]::FileDrop)
        if ($files -and $files.Count -ge 1) {
            Apply-DroppedFiles -Files $files -DroppedOnBox $sender -ZipBox $ZipBox -KcBox $KcBox
        }
    }.GetNewClosure())
}

# ---------------- Input highlight + Modern ----------------
$script:DefaultTextBoxBackColor = [System.Drawing.SystemColors]::Window
$script:DefaultTextBoxForeColor = [System.Drawing.SystemColors]::WindowText

function Clear-InputHighlight {
    param([Parameter(Mandatory)][System.Windows.Forms.TextBox]$Box)
    $Box.BackColor = $script:DefaultTextBoxBackColor
    $Box.ForeColor = $script:DefaultTextBoxForeColor
}

function Mark-InputInvalid {
    param([Parameter(Mandatory)][System.Windows.Forms.TextBox]$Box)
    $Box.BackColor = [System.Drawing.Color]::MistyRose
    $Box.ForeColor = [System.Drawing.Color]::FromArgb(120, 0, 0)
}

function Shake-Control {
    param(
        [Parameter(Mandatory)][System.Windows.Forms.Control]$Control,
        [int]$Amplitude = 6,
        [int]$Shakes = 8,
        [int]$IntervalMs = 15
    )

    if (-not $Control -or $Control.IsDisposed) { return }

    $orig = $Control.Location
    $tick = 0

    $timer = New-Object System.Windows.Forms.Timer
    $timer.Interval = $IntervalMs

    $timer.Add_Tick({
        try {
            $tick++
            $dir = if (($tick % 2) -eq 0) { -1 } else { 1 }
            $dx  = $dir * $Amplitude

            $Control.Location = New-Object System.Drawing.Point(($orig.X + $dx), $orig.Y)

            if ($tick -ge $Shakes) {
                $timer.Stop()
                $Control.Location = $orig
                $timer.Dispose()
            }
        } catch {
            try { $timer.Stop(); $timer.Dispose() } catch {}
        }
    }.GetNewClosure())

    $timer.Start()
}

# ---------------- Modern rounded look (C# older-compiler safe) ----------------
$uiNs = "RehaHashVerify.UI_" + ([Guid]::NewGuid().ToString("N"))

$uiCs = @"
using System;
using System.Drawing;
using System.Drawing.Drawing2D;
using System.Windows.Forms;

namespace $uiNs
{
    public class PillLabel : Control
    {
        public int CornerRadius { get; set; }
        public int BorderThickness { get; set; }
        public Color BorderColor { get; set; }

        public int ShadowOffsetX { get; set; }
        public int ShadowOffsetY { get; set; }
        public int ShadowBlur { get; set; }
        public Color ShadowColor { get; set; }

        public PillLabel()
        {
            SetStyle(ControlStyles.UserPaint |
                     ControlStyles.AllPaintingInWmPaint |
                     ControlStyles.OptimizedDoubleBuffer |
                     ControlStyles.ResizeRedraw, true);

            CornerRadius = 20;
            BorderThickness = 1;
            BorderColor = Color.FromArgb(20, 90, 60);

            ShadowOffsetX = 0;
            ShadowOffsetY = 3;
            ShadowBlur = 10;
            ShadowColor = Color.FromArgb(60, 0, 0, 0);

            Font = new Font("Segoe UI", 12, FontStyle.Bold);
            ForeColor = Color.White;
            BackColor = Color.FromArgb(25, 135, 84);
            Padding = new Padding(20, 10, 20, 10);
        }

        protected override void OnPaint(PaintEventArgs e)
        {
            base.OnPaint(e);

            e.Graphics.SmoothingMode = SmoothingMode.AntiAlias;
            e.Graphics.PixelOffsetMode = PixelOffsetMode.HighQuality;

            var rect = ClientRectangle;
            if (rect.Width <= 0 || rect.Height <= 0) return;

            if (ShadowBlur > 0)
            {
                for (int i = ShadowBlur; i >= 1; i--)
                {
                    int a = (int)(ShadowColor.A * (i / (float)(ShadowBlur * 2)));
                    if (a < 1) a = 1;

                    using (var shadowBrush = new SolidBrush(Color.FromArgb(a, ShadowColor.R, ShadowColor.G, ShadowColor.B)))
                    {
                        var sr = Rectangle.Inflate(rect, -1, -1);
                        sr.Offset(ShadowOffsetX, ShadowOffsetY);
                        sr = Rectangle.Inflate(sr, i/3, i/3);
                        using (var sp = RoundedRect(sr, CornerRadius + i/3))
                        {
                            e.Graphics.FillPath(shadowBrush, sp);
                        }
                    }
                }
            }

            var drawRect = Rectangle.Inflate(rect, -1, -1);
            using (var path = RoundedRect(drawRect, CornerRadius))
            using (var fill = new SolidBrush(BackColor))
            {
                e.Graphics.FillPath(fill, path);

                if (BorderThickness > 0)
                {
                    using (var pen = new Pen(BorderColor, BorderThickness))
                    {
                        pen.Alignment = PenAlignment.Inset;
                        e.Graphics.DrawPath(pen, path);
                    }
                }
            }

            var textRect = new Rectangle(
                rect.Left + Padding.Left,
                rect.Top + Padding.Top,
                rect.Width - Padding.Horizontal,
                rect.Height - Padding.Vertical
            );

            TextRenderer.DrawText(
                e.Graphics,
                Text,
                Font,
                textRect,
                ForeColor,
                TextFormatFlags.HorizontalCenter |
                TextFormatFlags.VerticalCenter |
                TextFormatFlags.EndEllipsis |
                TextFormatFlags.NoPadding
            );
        }

        private static GraphicsPath RoundedRect(Rectangle r, int radius)
        {
            var path = new GraphicsPath();
            int rr = Math.Max(2, radius);
            int d = rr * 2;
            if (d > r.Width) d = r.Width;
            if (d > r.Height) d = r.Height;

            var arc = new Rectangle(r.Location, new Size(d, d));

            path.AddArc(arc, 180, 90);
            arc.X = r.Right - d;
            path.AddArc(arc, 270, 90);
            arc.Y = r.Bottom - d;
            path.AddArc(arc, 0, 90);
            arc.X = r.Left;
            path.AddArc(arc, 90, 90);

            path.CloseFigure();
            return path;
        }

        public void AutoSizeToContent()
        {
            using (var g = CreateGraphics())
            {
                var sz = TextRenderer.MeasureText(g, Text, Font,
                    new Size(int.MaxValue, int.MaxValue),
                    TextFormatFlags.NoPadding);

                Width  = sz.Width + Padding.Horizontal + 18;
                Height = sz.Height + Padding.Vertical + 14;
            }
        }
    }
}
"@

$uiTypes = Add-Type -Language CSharp -TypeDefinition $uiCs -ReferencedAssemblies @(
    [System.Drawing.Color].Assembly.Location,
    [System.Windows.Forms.Form].Assembly.Location
) -PassThru

$PillLabelType = $uiTypes | Where-Object FullName -eq "$uiNs.PillLabel"
if (-not $PillLabelType) { throw "Failed to compile PillLabel type." }

# ---------------- Hash worker (C#) with unique namespace ----------------
$hashNs = "RehaHashVerify.Hash_" + ([Guid]::NewGuid().ToString("N"))

$hashCs = @"
using System;
using System.IO;
using System.Security.Cryptography;
using System.ComponentModel;
using System.Collections.Generic;

namespace $hashNs {

public class HashJobArgs {
    public string ZipPath;
    public string KcPath;

    public string CaseNum;
    public string ItemNum;
    public string Examiner;

    public string ZipExpSHA;
    public string ZipExpMD5;
    public string KcExpSHA;
    public string KcExpMD5;
}

public class HashWorker {

    private static string NormalizeHash(string h) {
        if (String.IsNullOrWhiteSpace(h)) return "";
        string s = h.Replace(" ", "").Replace("\t","").Replace("\r","").Replace("\n","").Trim();
        return s.ToUpperInvariant();
    }

    private static bool NeedsExtendedPath(string fullPath) {
        if (String.IsNullOrWhiteSpace(fullPath)) return false;
        return fullPath.Length >= 240;
    }

    private static string ToExtendedPath(string fullPath) {
        if (String.IsNullOrWhiteSpace(fullPath)) return fullPath;
        if (fullPath.StartsWith(@"\\", StringComparison.Ordinal)) {
            string unc = fullPath.TrimStart('\\');
            return @"\\?\UNC\" + unc;
        }
        return @"\\?\" + fullPath;
    }

    private static string HashFileWithProgress(
        BackgroundWorker bw,
        string path,
        string algorithm,
        int basePct,
        int spanPct)
    {
        if (String.IsNullOrWhiteSpace(path))
            throw new InvalidOperationException("File path was empty.");

        string full = Path.GetFullPath(path);
        var fi = new FileInfo(full);
        long total = fi.Length;
        if (total <= 0) throw new InvalidOperationException("File size is zero or could not be read: " + full);

        byte[] buffer = new byte[4 * 1024 * 1024];
        long readSoFar = 0;

        var state = new Dictionary<string, object>();
        state["Path"] = full;
        state["Algorithm"] = algorithm;
        state["BytesRead"] = 0L;
        state["TotalBytes"] = total;

        HashAlgorithm hasher;
        if (String.Equals(algorithm, "SHA256", StringComparison.OrdinalIgnoreCase))
            hasher = SHA256.Create();
        else if (String.Equals(algorithm, "MD5", StringComparison.OrdinalIgnoreCase))
            hasher = MD5.Create();
        else
            throw new InvalidOperationException("Unsupported algorithm: " + algorithm);

        using (hasher)
        {
            string openPath = full;
            if (NeedsExtendedPath(full)) openPath = ToExtendedPath(full);

            FileStream fs = null;
            try {
                fs = File.Open(openPath, FileMode.Open, FileAccess.Read, FileShare.Read);
            } catch (PathTooLongException) {
                fs = File.Open(ToExtendedPath(full), FileMode.Open, FileAccess.Read, FileShare.Read);
            } catch (IOException) {
                if (!openPath.StartsWith(@"\\?\", StringComparison.Ordinal)) {
                    fs = File.Open(ToExtendedPath(full), FileMode.Open, FileAccess.Read, FileShare.Read);
                } else {
                    throw;
                }
            }

            using (fs)
            {
                int bytesRead;
                while ((bytesRead = fs.Read(buffer, 0, buffer.Length)) > 0)
                {
                    if (bw.CancellationPending)
                        throw new OperationCanceledException("Cancelled");

                    hasher.TransformBlock(buffer, 0, bytesRead, null, 0);
                    readSoFar += bytesRead;

                    int pct = basePct + (int)Math.Floor(((double)readSoFar / (double)total) * spanPct);
                    if (pct > basePct + spanPct) pct = basePct + spanPct;

                    state["BytesRead"] = readSoFar;
                    bw.ReportProgress(pct, state);
                }

                hasher.TransformFinalBlock(new byte[0], 0, 0);
                return BitConverter.ToString(hasher.Hash).Replace("-", "").ToUpperInvariant();
            }
        }
    }

    private static Dictionary<string, object> ComputeSection(
        BackgroundWorker bw,
        string filePath,
        string expSha,
        string expMd5,
        int basePct,
        int spanPct)
    {
        int shaSpan = (int)Math.Round(spanPct * 0.60);
        int md5Span = spanPct - shaSpan;

        string shaActual = HashFileWithProgress(bw, filePath, "SHA256", basePct, shaSpan);
        string md5Actual = HashFileWithProgress(bw, filePath, "MD5", basePct + shaSpan, md5Span);

        string shaExpected = NormalizeHash(expSha);
        string md5Expected = NormalizeHash(expMd5);

        bool shaOk = String.IsNullOrWhiteSpace(shaExpected) ? true : (shaExpected == shaActual);
        bool md5Ok = String.IsNullOrWhiteSpace(md5Expected) ? true : (md5Expected == md5Actual);

        string overall = (shaOk && md5Ok) ? "PASS" : "FAIL";

        var sec = new Dictionary<string, object>();
        sec["FilePath"] = filePath;
        sec["FileName"] = Path.GetFileName(filePath);
        sec["SizeBytes"] = new FileInfo(filePath).Length;

        sec["SHA256_Expected"] = shaExpected;
        sec["SHA256_Actual"] = shaActual;
        sec["SHA256_Result"] = shaOk ? "PASS" : "FAIL";

        sec["MD5_Expected"] = md5Expected;
        sec["MD5_Actual"] = md5Actual;
        sec["MD5_Result"] = md5Ok ? "PASS" : "FAIL";

        sec["FileOverall"] = overall;
        return sec;
    }

    public void DoWork(object sender, DoWorkEventArgs e) {
        var bw = (BackgroundWorker)sender;
        var a = (HashJobArgs)e.Argument;

        bool hasZip = !String.IsNullOrWhiteSpace(a.ZipPath);
        bool hasKc  = !String.IsNullOrWhiteSpace(a.KcPath);

        Dictionary<string, object> zipSec = null;
        Dictionary<string, object> kcSec  = null;

        if (hasZip && hasKc) {
            zipSec = ComputeSection(bw, a.ZipPath, a.ZipExpSHA, a.ZipExpMD5, 0, 50);
            kcSec  = ComputeSection(bw, a.KcPath,  a.KcExpSHA,  a.KcExpMD5,  50, 50);
        } else if (hasZip) {
            zipSec = ComputeSection(bw, a.ZipPath, a.ZipExpSHA, a.ZipExpMD5, 0, 100);
        } else if (hasKc) {
            kcSec  = ComputeSection(bw, a.KcPath,  a.KcExpSHA,  a.KcExpMD5,  0, 100);
        }

        string overall = "PASS";
        if (zipSec != null && (string)zipSec["FileOverall"] == "FAIL") overall = "FAIL";
        if (kcSec  != null && (string)kcSec["FileOverall"]  == "FAIL") overall = "FAIL";

        var result = new Dictionary<string, object>();
        result["Overall"] = overall;
        result["ZipSection"] = zipSec;
        result["KcSection"]  = kcSec;

        var meta = new Dictionary<string, object>();
        meta["CaseNumber"] = a.CaseNum ?? "";
        meta["ItemNumber"] = a.ItemNum ?? "";
        meta["Examiner"]   = a.Examiner ?? "";
        result["Meta"] = meta;

        e.Result = result;
    }
}

}
"@

$hashTypes = Add-Type -Language CSharp -TypeDefinition $hashCs -ReferencedAssemblies @(
    [System.Security.Cryptography.SHA256].Assembly.Location,
    [System.ComponentModel.BackgroundWorker].Assembly.Location,
    [System.IO.File].Assembly.Location
) -PassThru

$HashJobType    = $hashTypes | Where-Object FullName -eq "$hashNs.HashJobArgs"
$HashWorkerType = $hashTypes | Where-Object FullName -eq "$hashNs.HashWorker"
if (-not $HashJobType -or -not $HashWorkerType) { throw "Failed to compile hash worker types." }

# ---------------- UI ----------------
$form = New-Object System.Windows.Forms.Form
$form.Text            = "$AppName - $BuildStamp"
$form.Size            = New-Object System.Drawing.Size(940, 930)
$form.StartPosition   = "CenterScreen"
$form.MaximizeBox     = $false
$form.FormBorderStyle = "FixedDialog"
$form.BackColor       = [System.Drawing.Color]::FromArgb(246,247,249)

try {
    $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName
    if ($selfPath -and (Test-Path -LiteralPath $selfPath -PathType Leaf)) {
        $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($selfPath)
    }
} catch {}

# Header
$hdr = New-Object System.Windows.Forms.Panel
$hdr.Location = New-Object System.Drawing.Point(0,0)
$hdr.Size = New-Object System.Drawing.Size($form.ClientSize.Width, 84)
$hdr.BackColor = [System.Drawing.Color]::White
$hdr.Anchor = "Top,Left,Right"
$form.Controls.Add($hdr)

$lblTitle = New-Object System.Windows.Forms.Label
$lblTitle.AutoSize = $true
$lblTitle.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 13)
$lblTitle.Text = $AppName
$lblTitle.Location = New-Object System.Drawing.Point(14, 14)
$hdr.Controls.Add($lblTitle)

$lblSub = New-Object System.Windows.Forms.Label
$lblSub.AutoSize = $true
$lblSub.Font = New-Object System.Drawing.Font("Segoe UI", 9)
$lblSub.ForeColor = [System.Drawing.Color]::DimGray
$lblSub.Text = "$BuildStamp  |  $AppOwner"
$lblSub.Location = New-Object System.Drawing.Point(16, 44)
$hdr.Controls.Add($lblSub)

# Big pill status (right)
$script:lblChip = New-Object ($PillLabelType.FullName)
$script:lblChip.Text = "READY"
$script:lblChip.Font = New-Object System.Drawing.Font("Segoe UI Semibold", 12)
$script:lblChip.Padding = New-Object System.Windows.Forms.Padding(26, 12, 26, 12)
$script:lblChip.CornerRadius = 22
$script:lblChip.BorderThickness = 1
$script:lblChip.BorderColor = [System.Drawing.Color]::FromArgb(210, 230, 220)
$script:lblChip.ShadowOffsetX = 0
$script:lblChip.ShadowOffsetY = 4
$script:lblChip.ShadowBlur = 10
$script:lblChip.ShadowColor = [System.Drawing.Color]::FromArgb(70, 0, 0, 0)
$script:lblChip.AutoSizeToContent()
$script:lblChip.Location = New-Object System.Drawing.Point(($form.ClientSize.Width - $script:lblChip.Width - 18), 18)
$script:lblChip.Anchor = "Top,Right"
$hdr.Controls.Add($script:lblChip)

function Set-ChipState {
    param([string]$Text, [int[]]$Rgb)
    $script:lblChip.Text = $Text
    $script:lblChip.BackColor = [System.Drawing.Color]::FromArgb($Rgb[0], $Rgb[1], $Rgb[2])
    $script:lblChip.AutoSizeToContent()
    $script:lblChip.Location = New-Object System.Drawing.Point(($form.ClientSize.Width - $script:lblChip.Width - 18), 18)
    $script:lblChip.Invalidate()
}

$ContentTop = $hdr.Bottom + 10

# Dialog
$openFile = New-Object System.Windows.Forms.OpenFileDialog
$openFile.Title  = "Select file"
$openFile.Filter = "All files (*.*)|*.*"

# Groups
$grpFiles = New-Object System.Windows.Forms.GroupBox
$grpFiles.Text = "Files to Verify (drag-and-drop ZIP + Keychain)"
$grpFiles.Location = New-Object System.Drawing.Point(12, $ContentTop)
$grpFiles.Size = New-Object System.Drawing.Size(900, 140)
$form.Controls.Add($grpFiles)

$Left=12; $LabelW=90; $Gap=8; $BtnW=100; $BtnH=28
$txtX = $Left + $LabelW + $Gap
$btnX = 785
$txtW = $btnX - $txtX - 10

$lblZip = New-Object System.Windows.Forms.Label
$lblZip.Text="ZIP:"
$lblZip.Location=New-Object System.Drawing.Point($Left,30)
$lblZip.Size=New-Object System.Drawing.Size($LabelW,22)
$lblZip.TextAlign=[System.Drawing.ContentAlignment]::MiddleLeft
$grpFiles.Controls.Add($lblZip)

$txtZip = New-Object System.Windows.Forms.TextBox
$txtZip.Location=New-Object System.Drawing.Point($txtX,27)
$txtZip.Size=New-Object System.Drawing.Size($txtW,24)
$txtZip.ReadOnly=$true
$grpFiles.Controls.Add($txtZip)

$btnZip = New-Object System.Windows.Forms.Button
$btnZip.Text="Browse..."
$btnZip.Location=New-Object System.Drawing.Point($btnX,25)
$btnZip.Size=New-Object System.Drawing.Size($BtnW,$BtnH)
$grpFiles.Controls.Add($btnZip)

$lblKC = New-Object System.Windows.Forms.Label
$lblKC.Text="Keychain:"
$lblKC.Location=New-Object System.Drawing.Point($Left,73)
$lblKC.Size=New-Object System.Drawing.Size($LabelW,22)
$lblKC.TextAlign=[System.Drawing.ContentAlignment]::MiddleLeft
$grpFiles.Controls.Add($lblKC)

$txtKC = New-Object System.Windows.Forms.TextBox
$txtKC.Location=New-Object System.Drawing.Point($txtX,70)
$txtKC.Size=New-Object System.Drawing.Size($txtW,24)
$txtKC.ReadOnly=$true
$grpFiles.Controls.Add($txtKC)

$btnKC = New-Object System.Windows.Forms.Button
$btnKC.Text="Browse..."
$btnKC.Location=New-Object System.Drawing.Point($btnX,68)
$btnKC.Size=New-Object System.Drawing.Size($BtnW,$BtnH)
$grpFiles.Controls.Add($btnKC)

Enable-DropToBox -Box $txtZip -ZipBox $txtZip -KcBox $txtKC
Enable-DropToBox -Box $txtKC  -ZipBox $txtZip -KcBox $txtKC

$grpMeta = New-Object System.Windows.Forms.GroupBox
$grpMeta.Text = "Optional Metadata"
$grpMeta.Location = New-Object System.Drawing.Point(12, ($grpFiles.Bottom + 10))
$grpMeta.Size = New-Object System.Drawing.Size(900, 85)
$form.Controls.Add($grpMeta)

$lblCase = New-Object System.Windows.Forms.Label
$lblCase.Text="Case #:"
$lblCase.Location=New-Object System.Drawing.Point(12,34)
$lblCase.AutoSize=$true
$grpMeta.Controls.Add($lblCase)

$txtCase = New-Object System.Windows.Forms.TextBox
$txtCase.Location=New-Object System.Drawing.Point(70,31)
$txtCase.Size=New-Object System.Drawing.Size(230,24)
$grpMeta.Controls.Add($txtCase)

$lblItem = New-Object System.Windows.Forms.Label
$lblItem.Text="Item #:"
$lblItem.Location=New-Object System.Drawing.Point(320,34)
$lblItem.AutoSize=$true
$grpMeta.Controls.Add($lblItem)

$txtItem = New-Object System.Windows.Forms.TextBox
$txtItem.Location=New-Object System.Drawing.Point(375,31)
$txtItem.Size=New-Object System.Drawing.Size(180,24)
$grpMeta.Controls.Add($txtItem)

$lblExam = New-Object System.Windows.Forms.Label
$lblExam.Text="Examiner:"
$lblExam.Location=New-Object System.Drawing.Point(575,34)
$lblExam.AutoSize=$true
$grpMeta.Controls.Add($lblExam)

$txtExam = New-Object System.Windows.Forms.TextBox
$txtExam.Location=New-Object System.Drawing.Point(645,31)
$txtExam.Size=New-Object System.Drawing.Size(245,24)
$grpMeta.Controls.Add($txtExam)

$grpExp = New-Object System.Windows.Forms.GroupBox
$grpExp.Text = "Expected Hashes (optional)"
$grpExp.Location = New-Object System.Drawing.Point(12, ($grpMeta.Bottom + 10))
$grpExp.Size = New-Object System.Drawing.Size(900, 210)
$form.Controls.Add($grpExp)

$lblZipSHA = New-Object System.Windows.Forms.Label
$lblZipSHA.Text="ZIP SHA-256:"
$lblZipSHA.Location=New-Object System.Drawing.Point(12,35)
$lblZipSHA.AutoSize=$true
$grpExp.Controls.Add($lblZipSHA)

$txtZipSHA = New-Object System.Windows.Forms.TextBox
$txtZipSHA.Location=New-Object System.Drawing.Point(120,32)
$txtZipSHA.Size=New-Object System.Drawing.Size(770,24)
$grpExp.Controls.Add($txtZipSHA)

$lblZipMD5 = New-Object System.Windows.Forms.Label
$lblZipMD5.Text="ZIP MD5:"
$lblZipMD5.Location=New-Object System.Drawing.Point(12,70)
$lblZipMD5.AutoSize=$true
$grpExp.Controls.Add($lblZipMD5)

$txtZipMD5 = New-Object System.Windows.Forms.TextBox
$txtZipMD5.Location=New-Object System.Drawing.Point(120,67)
$txtZipMD5.Size=New-Object System.Drawing.Size(770,24)
$grpExp.Controls.Add($txtZipMD5)

$lblKCSHA = New-Object System.Windows.Forms.Label
$lblKCSHA.Text="KC SHA-256:"
$lblKCSHA.Location=New-Object System.Drawing.Point(12,125)
$lblKCSHA.AutoSize=$true
$grpExp.Controls.Add($lblKCSHA)

$txtKCSHA = New-Object System.Windows.Forms.TextBox
$txtKCSHA.Location=New-Object System.Drawing.Point(120,122)
$txtKCSHA.Size=New-Object System.Drawing.Size(770,24)
$grpExp.Controls.Add($txtKCSHA)

$lblKCMD5 = New-Object System.Windows.Forms.Label
$lblKCMD5.Text="KC MD5:"
$lblKCMD5.Location=New-Object System.Drawing.Point(12,160)
$lblKCMD5.AutoSize=$true
$grpExp.Controls.Add($lblKCMD5)

$txtKCMD5 = New-Object System.Windows.Forms.TextBox
$txtKCMD5.Location=New-Object System.Drawing.Point(120,157)
$txtKCMD5.Size=New-Object System.Drawing.Size(770,24)
$grpExp.Controls.Add($txtKCMD5)

# Auto-clear highlight when user edits (register ONCE)
$txtZipSHA.Add_TextChanged({ Clear-InputHighlight -Box $txtZipSHA })
$txtZipMD5.Add_TextChanged({ Clear-InputHighlight -Box $txtZipMD5 })
$txtKCSHA.Add_TextChanged({ Clear-InputHighlight -Box $txtKCSHA })
$txtKCMD5.Add_TextChanged({ Clear-InputHighlight -Box $txtKCMD5 })

# Buttons
$btnY = $grpExp.Bottom + 12

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Verify and Generate Report"
$btnRun.Location = New-Object System.Drawing.Point(12, $btnY)
$btnRun.Size = New-Object System.Drawing.Size(280, 40)
$form.Controls.Add($btnRun)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Cancel"
$btnCancel.Location = New-Object System.Drawing.Point(($btnRun.Right + 10), $btnY)
$btnCancel.Size = New-Object System.Drawing.Size(100, 40)
$btnCancel.Enabled = $false
$form.Controls.Add($btnCancel)

$btnCopyPath = New-Object System.Windows.Forms.Button
$btnCopyPath.Text = "Copy Report Path"
$btnCopyPath.Location = New-Object System.Drawing.Point(($btnCancel.Right + 10), $btnY)
$btnCopyPath.Size = New-Object System.Drawing.Size(160, 40)
$btnCopyPath.Enabled = $false
$form.Controls.Add($btnCopyPath)

$btnOpenFolder = New-Object System.Windows.Forms.Button
$btnOpenFolder.Text = "Open Folder"
$btnOpenFolder.Location = New-Object System.Drawing.Point(($btnCopyPath.Right + 10), $btnY)
$btnOpenFolder.Size = New-Object System.Drawing.Size(130, 40)
$btnOpenFolder.Enabled = $false
$form.Controls.Add($btnOpenFolder)

$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Status: Select ZIP and/or Keychain."
$lblStatus.Location = New-Object System.Drawing.Point(12, ($btnRun.Bottom + 12))
$lblStatus.AutoSize = $true
$form.Controls.Add($lblStatus)

$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(12, ($lblStatus.Bottom + 6))
$progressBar.Size = New-Object System.Drawing.Size(800, 18)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$form.Controls.Add($progressBar)

$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Location = New-Object System.Drawing.Point(($progressBar.Right + 10), $progressBar.Top)
$lblProgress.AutoSize = $true
$lblProgress.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($lblProgress)

$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtOutput.Location = New-Object System.Drawing.Point(12, ($progressBar.Bottom + 10))
$txtOutput.Size = New-Object System.Drawing.Size(900, 260)
$form.Controls.Add($txtOutput)

$form.ClientSize = New-Object System.Drawing.Size(940, ($txtOutput.Bottom + 20))

# Browse handlers
$btnZip.Add_Click({
    if ($openFile.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtZip.Text = Normalize-InputPath $openFile.FileName
    }
})
$btnKC.Add_Click({
    if ($openFile.ShowDialog() -eq [System.Windows.Forms.DialogResult]::OK) {
        $txtKC.Text = Normalize-InputPath $openFile.FileName
    }
})

# ---------------- Background Worker ----------------
$worker = New-Object System.ComponentModel.BackgroundWorker
$worker.WorkerReportsProgress = $true
$worker.WorkerSupportsCancellation = $true

$hashWorker = New-Object ($HashWorkerType.FullName)
$mi  = $hashWorker.GetType().GetMethod("DoWork")
$del = [System.Delegate]::CreateDelegate([System.ComponentModel.DoWorkEventHandler], $hashWorker, $mi)
$worker.add_DoWork($del)

# Shared state must be script-scoped - event handlers
$script:lastMeta = $null
$script:lastZipSection = $null
$script:lastKCSection = $null
$script:lastDefaultReportPath = $null

$worker.Add_ProgressChanged({
    param($sender, $e)

    $pct = $e.ProgressPercentage
    if ($pct -lt 0) { $pct = 0 }
    if ($pct -gt 100) { $pct = 100 }
    $progressBar.Value = $pct

    $u = $e.UserState
    if ($u) {
        $doneGB  = [math]::Round(($u["BytesRead"] / 1GB), 2)
        $totalGB = [math]::Round(($u["TotalBytes"] / 1GB), 2)
        $lblProgress.Text = "$doneGB / $totalGB GB"
        $lblStatus.Text = "Status: Hashing $($u["Algorithm"])... $(Split-Path $u["Path"] -Leaf)"
    }
})

$worker.Add_RunWorkerCompleted({
    param($sender, $e)

    $btnRun.Enabled = $true
    $btnCancel.Enabled = $false

    if ($e.Cancelled) {
        Set-ChipState -Text "CANCELLED" -Rgb @(108,117,125)
        $lblStatus.Text = "Status: Cancelled"
        $txtOutput.Text = "Cancelled by user."
        return
    }

    if ($e.Error) {
        $msg = $e.Error.ToString()
        if ($e.Error -is [System.OperationCanceledException] -or $msg -match 'OperationCanceledException') {
            Set-ChipState -Text "CANCELLED" -Rgb @(108,117,125)
            $lblStatus.Text = "Status: Cancelled"
            $txtOutput.Text = "Cancelled by user."
            return
        }

        Set-ChipState -Text "FAILED" -Rgb @(220,53,69)
        $lblStatus.Text = "Status: ERROR"
        $txtOutput.Text = "ERROR:`r`n$($e.Error.ToString())"
        [System.Windows.Forms.MessageBox]::Show($e.Error.ToString(), "Error", "OK", "Error") | Out-Null
        return
    }

    $result = $e.Result
    $overall = $result["Overall"]

    $zipSection = Convert-DictToHashtable $result["ZipSection"]
    $kcSection  = Convert-DictToHashtable $result["KcSection"]
    $metaDict   = Convert-DictToHashtable $result["Meta"]

    $meta = @{
        GeneratedLocal = (Get-Date).ToString("yyyy-MM-dd HH:mm:ss zzz")
        CaseNumber     = $metaDict["CaseNumber"]
        ItemNumber     = $metaDict["ItemNumber"]
        Examiner       = $metaDict["Examiner"]
        OverallResult  = $overall
    }

    $baseDir = if ($zipSection) { Split-Path -Parent $zipSection.FilePath } else { Split-Path -Parent $kcSection.FilePath }
    $script:lastDefaultReportPath = Build-DefaultReportPath -BaseDir $baseDir -CaseNumber $meta.CaseNumber -ItemNumber $meta.ItemNumber

    Write-CombinedReport -ReportPath $script:lastDefaultReportPath -Meta $meta -ZipSection $zipSection -KeychainSection $kcSection

    $summary = @()
    if ($zipSection) { $summary += "ZIP Result: $($zipSection.FileOverall)" }
    if ($kcSection)  { $summary += "Keychain Result: $($kcSection.FileOverall)" }
    $summary += "OVERALL: $overall"
    $summary += "REPORT SAVED: $script:lastDefaultReportPath"

    $txtOutput.Text = ($summary -join "`r`n")
    Set-ChipState -Text "COMPLETE" -Rgb @(25,135,84)
    $lblStatus.Text = "Status: Done. Overall = $overall"

    $btnCopyPath.Enabled   = $true
    $btnOpenFolder.Enabled = $true

    $script:lastMeta       = $meta
    $script:lastZipSection = $zipSection
    $script:lastKCSection  = $kcSection
})

$btnCancel.Add_Click({
    if ($worker.IsBusy) {
        $btnCancel.Enabled = $false
        $lblStatus.Text = "Status: Cancelling..."
        $worker.CancelAsync()
    }
})

# use $script:lastDefaultReportPath
$btnCopyPath.Add_Click({
    if (-not [string]::IsNullOrWhiteSpace($script:lastDefaultReportPath)) {
        [System.Windows.Forms.Clipboard]::SetText($script:lastDefaultReportPath)
        [System.Windows.Forms.MessageBox]::Show("Copied:`n$script:lastDefaultReportPath", "Copied", "OK", "Information") | Out-Null
    } else {
        [System.Windows.Forms.MessageBox]::Show("No report path available yet. Run a verification first.", "Not Ready", "OK", "Warning") | Out-Null
    }
})

# FIXED: uses $script:lastDefaultReportPath
$btnOpenFolder.Add_Click({
    $p = $script:lastDefaultReportPath
    if ([string]::IsNullOrWhiteSpace($p)) {
        [System.Windows.Forms.MessageBox]::Show("No report path available yet. Run a verification first.", "Not Ready", "OK", "Warning") | Out-Null
        return
    }

    if (Test-Path -LiteralPath $p -PathType Leaf) {
        Start-Process explorer.exe "/select,`"$p`""
        return
    }

    $dir = Split-Path -Parent $p
    if ($dir -and (Test-Path -LiteralPath $dir -PathType Container)) {
        Start-Process explorer.exe "`"$dir`""
        return
    }

    [System.Windows.Forms.MessageBox]::Show("Report path not found:`n$p", "Not Found", "OK", "Error") | Out-Null
})

# ---------------- Run ----------------
$btnRun.Add_Click({
    try {
        # Reset highlights at start of run
        Clear-InputHighlight -Box $txtZipSHA
        Clear-InputHighlight -Box $txtZipMD5
        Clear-InputHighlight -Box $txtKCSHA
        Clear-InputHighlight -Box $txtKCMD5

        $zipPath = Normalize-InputPath -Path $txtZip.Text
        $kcPath  = Normalize-InputPath -Path $txtKC.Text
        $txtZip.Text = $zipPath
        $txtKC.Text  = $kcPath

        $zipReport = Get-IllegalPathCharsReport -p $zipPath
        $kcReport  = Get-IllegalPathCharsReport -p $kcPath

        if ($zipReport -ne "No illegal chars detected.") {
            [System.Windows.Forms.MessageBox]::Show("ZIP path issue:`r`n$zipReport`r`n`r`nValue:`r`n$zipPath", "Invalid ZIP Path", "OK", "Error") | Out-Null
            return
        }
        if ($kcReport -ne "No illegal chars detected.") {
            [System.Windows.Forms.MessageBox]::Show("Keychain path issue:`r`n$kcReport`r`n`r`nValue:`r`n$kcPath", "Invalid Keychain Path", "OK", "Error") | Out-Null
            return
        }

        if (-not [string]::IsNullOrWhiteSpace($zipPath) -and -not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
            throw "ZIP file not found: <$zipPath>"
        }
        if (-not [string]::IsNullOrWhiteSpace($kcPath) -and -not (Test-Path -LiteralPath $kcPath -PathType Leaf)) {
            throw "Keychain file not found: <$kcPath>"
        }
        if ([string]::IsNullOrWhiteSpace($zipPath) -and [string]::IsNullOrWhiteSpace($kcPath)) {
            [System.Windows.Forms.MessageBox]::Show("Select at least one file (ZIP and/or Keychain).", "Missing Files", "OK", "Warning") | Out-Null
            return
        }

        # ---- Expected hashes (highlight + shake + field-specific message) ----
        $v1 = Test-ExpectedHash -Value $txtZipSHA.Text -Alg SHA256 -LabelForError "ZIP SHA-256"
        if (-not $v1.Ok) {
            Mark-InputInvalid -Box $txtZipSHA
            $txtZipSHA.Focus()
            Shake-Control -Control $txtZipSHA
            [System.Windows.Forms.MessageBox]::Show($v1.Error, "Invalid Input", "OK", "Error") | Out-Null
            return
        }
        $txtZipSHA.Text = $v1.Normalized

        $v2 = Test-ExpectedHash -Value $txtZipMD5.Text -Alg MD5 -LabelForError "ZIP MD5"
        if (-not $v2.Ok) {
            Mark-InputInvalid -Box $txtZipMD5
            $txtZipMD5.Focus()
            Shake-Control -Control $txtZipMD5
            [System.Windows.Forms.MessageBox]::Show($v2.Error, "Invalid Input", "OK", "Error") | Out-Null
            return
        }
        $txtZipMD5.Text = $v2.Normalized

        $v3 = Test-ExpectedHash -Value $txtKCSHA.Text -Alg SHA256 -LabelForError "KC SHA-256"
        if (-not $v3.Ok) {
            Mark-InputInvalid -Box $txtKCSHA
            $txtKCSHA.Focus()
            Shake-Control -Control $txtKCSHA
            [System.Windows.Forms.MessageBox]::Show($v3.Error, "Invalid Input", "OK", "Error") | Out-Null
            return
        }
        $txtKCSHA.Text = $v3.Normalized

        $v4 = Test-ExpectedHash -Value $txtKCMD5.Text -Alg MD5 -LabelForError "KC MD5"
        if (-not $v4.Ok) {
            Mark-InputInvalid -Box $txtKCMD5
            $txtKCMD5.Focus()
            Shake-Control -Control $txtKCMD5
            [System.Windows.Forms.MessageBox]::Show($v4.Error, "Invalid Input", "OK", "Error") | Out-Null
            return
        }
        $txtKCMD5.Text = $v4.Normalized

        # ---- Start worker ----
        $btnRun.Enabled = $false
        $btnCancel.Enabled = $true
        $btnCopyPath.Enabled = $false
        $btnOpenFolder.Enabled = $false

        Set-ChipState -Text "RUNNING" -Rgb @(13,110,253)
        $progressBar.Value = 0
        $lblProgress.Text = ""
        $txtOutput.Clear()
        $lblStatus.Text = "Status: Starting..."
        $form.Refresh()

        $job = New-Object ($HashJobType.FullName)
        $job.ZipPath   = $zipPath
        $job.KcPath    = $kcPath
        $job.CaseNum   = $txtCase.Text.Trim()
        $job.ItemNum   = $txtItem.Text.Trim()
        $job.Examiner  = $txtExam.Text.Trim()
        $job.ZipExpSHA = $txtZipSHA.Text
        $job.ZipExpMD5 = $txtZipMD5.Text
        $job.KcExpSHA  = $txtKCSHA.Text
        $job.KcExpMD5  = $txtKCMD5.Text

        $worker.RunWorkerAsync($job)
    }
    catch {
        Set-ChipState -Text "FAILED" -Rgb @(220,53,69)
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Run Failed", "OK", "Error") | Out-Null
        $btnRun.Enabled = $true
        $btnCancel.Enabled = $false
        $lblStatus.Text = "Status: ERROR"
        $txtOutput.Text = "ERROR:`r`n$($_.Exception.ToString())"
    }
})

[void]$form.ShowDialog()
