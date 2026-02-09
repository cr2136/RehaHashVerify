<#
HashVerify-GrayKey-v6.2-PS51.ps1

Fixes:
- Normalizes file paths (trims, strips quotes, converts file:/// URI, rejects illegal chars)
- Uses Test-Path -LiteralPath
- Drag & drop supports multi-file (drop ZIP + Keychain together onto either box)
- Run button normalizes paths again before starting BackgroundWorker (defense-in-depth)

Targets:
- ZIP + optional Keychain
- SHA-256 first, then MD5
- Optional metadata in report header
- Accurate byte-based progress bar + cancel
- Default report saved in same folder as ZIP (else keychain)
- No PowerShell scriptblocks executed on BackgroundWorker thread (avoids runspace errors)

Designed for:
- PowerShell 5.1 (Desktop) / .NET Framework 4.x
#>

Add-Type -AssemblyName System.Windows.Forms
Add-Type -AssemblyName System.Drawing

$AppName    = "GrayKey Hash Verify"
$AppVersion = "6.2.0"
$BuildDate  = "2026-02-05"
$AppOwner   = "Curtis Reha"

$BuildStamp = "v$AppVersion ($BuildDate)"


# ---------------- Build reference list for Add-Type (PS 5.1 / .NET Framework) ----------------
function Get-AsmLocation([Type]$t) {
    try { return $t.Assembly.Location } catch { return $null }
}

$refPaths = New-Object System.Collections.Generic.List[string]

$mscorlib = Get-AsmLocation ([object])
if ($mscorlib -and -not $refPaths.Contains($mscorlib)) { $refPaths.Add($mscorlib) }

$systemDll = Get-AsmLocation ([System.ComponentModel.BackgroundWorker])
if ($systemDll -and -not $refPaths.Contains($systemDll)) { $refPaths.Add($systemDll) }

$systemCoreDll = Get-AsmLocation ([System.Linq.Enumerable])
if ($systemCoreDll -and -not $refPaths.Contains($systemCoreDll)) { $refPaths.Add($systemCoreDll) }

$winFormsDll = Get-AsmLocation ([System.Windows.Forms.Form])
if ($winFormsDll -and -not $refPaths.Contains($winFormsDll)) { $refPaths.Add($winFormsDll) }

$secDll = Get-AsmLocation ([System.Security.Cryptography.HashAlgorithm])
if ($secDll -and -not $refPaths.Contains($secDll)) { $refPaths.Add($secDll) }

try {
    $loaded = [System.Reflection.Assembly]::Load("System.Security")
    if ($loaded -and (Test-Path $loaded.Location) -and -not $refPaths.Contains($loaded.Location)) { $refPaths.Add($loaded.Location) }
} catch {}

# ---------------- C# worker (no runspace dependency on worker thread) ----------------
if ($DEBUG_CSHARP_DUMP) {
    $dumpPath = Join-Path $env:TEMP "GrayKeyHashVerify_CSharpDump.cs"
    Set-Content -Path $dumpPath -Value $cs -Encoding UTF8
    if ($cs -match '>>>') {
        [System.Windows.Forms.MessageBox]::Show("Found '>>>' inside embedded C#.`r`nDumped to:`r`n$dumpPath", "C# Marker Found", "OK", "Error") | Out-Null
    } else {
        [System.Windows.Forms.MessageBox]::Show("No '>>>' found by regex in embedded C#.`r`nDumped to:`r`n$dumpPath", "C# Dumped", "OK", "Information") | Out-Null
    }
}



Add-Type -Language CSharp -TypeDefinition @"
using System;
using System.IO;
using System.Security.Cryptography;
using System.ComponentModel;
using System.Collections.Generic;

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

    // Only use \\?\ long path prefix when needed
    private static string ToExtendedPath(string path) {
        if (String.IsNullOrWhiteSpace(path)) return path;
        string full = Path.GetFullPath(path);

        if (full.StartsWith(@"\\", StringComparison.Ordinal)) {
            string unc = full.TrimStart('\\');
            return @"\\?\UNC\" + unc;
        }

        return @"\\?\" + full;
    }

    private static string DumpChars(string s) {
        if (s == null) return "<null>";
        var sb = new System.Text.StringBuilder();
        for (int i = 0; i < s.Length; i++) {
            char c = s[i];
            int code = (int)c;
            string shown = Char.IsControl(c) ? "" : c.ToString();
            sb.AppendFormat("[{0}] U+{1:X4} '{2}' ", i, code, shown);
        }
        return sb.ToString();
    }

    private static string HashFileWithProgress(
        BackgroundWorker bw,
        string path,
        string algorithm,
        int basePct,
        int spanPct)
    {
        try {
            if (String.IsNullOrWhiteSpace(path))
                throw new InvalidOperationException("File path was empty.");

            // If the path is getting long, try extended prefix; otherwise keep normal path (most compatible)
            string openPath = path;
            if (path.Length >= 240) openPath = ToExtendedPath(path);

            var fi = new FileInfo(path);
            long total = fi.Length;
            if (total <= 0) throw new InvalidOperationException("File size is zero or could not be read: " + path);

            byte[] buffer = new byte[4 * 1024 * 1024]; // 4MB
            long readSoFar = 0;

            using (FileStream fs = File.Open(openPath, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                HashAlgorithm hasher;
                if (String.Equals(algorithm, "SHA256", StringComparison.OrdinalIgnoreCase))
                    hasher = SHA256.Create();
                else if (String.Equals(algorithm, "MD5", StringComparison.OrdinalIgnoreCase))
                    hasher = MD5.Create();
                else
                    throw new InvalidOperationException("Unsupported algorithm: " + algorithm);

                using (hasher)
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

                        var state = new Dictionary<string, object>();
                        state["Path"] = path;
                        state["Algorithm"] = algorithm;
                        state["BytesRead"] = readSoFar;
                        state["TotalBytes"] = total;

                        bw.ReportProgress(pct, state);
                    }

                    hasher.TransformFinalBlock(new byte[0], 0, 0);
                    return BitConverter.ToString(hasher.Hash).Replace("-", "").ToUpperInvariant();
                }
            }
        }
        catch (Exception ex) {
            throw new InvalidOperationException(
                "HashFileWithProgress failed. path=[" + path + "] chars=" + DumpChars(path),
                ex
            );
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
        var bw = sender as BackgroundWorker;
        var a = e.Argument as HashJobArgs;

        Dictionary<string, object> zipSec = null;
        Dictionary<string, object> kcSec = null;

        if (!String.IsNullOrWhiteSpace(a.ZipPath))
            zipSec = ComputeSection(bw, a.ZipPath, a.ZipExpSHA, a.ZipExpMD5, 0, 100);

        if (!String.IsNullOrWhiteSpace(a.KcPath))
            kcSec = ComputeSection(bw, a.KcPath, a.KcExpSHA, a.KcExpMD5, 0, 100);

        string overall = "PASS";
        if (zipSec != null && (string)zipSec["FileOverall"] == "FAIL") overall = "FAIL";
        if (kcSec  != null && (string)kcSec["FileOverall"]  == "FAIL") overall = "FAIL";

        var result = new Dictionary<string, object>();
        result["Overall"] = overall;
        result["ZipSection"] = zipSec;
        result["KcSection"] = kcSec;

        var meta = new Dictionary<string, object>();
        meta["CaseNumber"] = a.CaseNum ?? "";
        meta["ItemNumber"] = a.ItemNum ?? "";
        meta["Examiner"]   = a.Examiner ?? "";
        result["Meta"] = meta;

        e.Result = result;
    }
}
"@


# ---------------- PowerShell helpers ----------------
function Build-DefaultReportPath {
    param(
        [Parameter(Mandatory)][string]$BaseDir,
        [string]$CaseNumber,
        [string]$ItemNumber
    )
    $ts  = (Get-Date).ToString("yyyyMMdd_HHmmss")
    $caseTag = ""
    if ($CaseNumber) { $caseTag += "_CASE-$($CaseNumber.Trim())" }
    if ($ItemNumber) { $caseTag += "_ITEM-$($ItemNumber.Trim())" }
    Join-Path $BaseDir ("HashVerify_GrayKey{0}_{1}.txt" -f $caseTag, $ts)
}

function Convert-DictToHashtable($dict) {
    if (-not $dict) { return $null }
    $ht = @{}
    foreach ($k in $dict.Keys) { $ht[$k] = $dict[$k] }
    return $ht
}

function Write-CombinedReport {
    param(
        [Parameter(Mandatory)][string]$ReportPath,
        [Parameter(Mandatory)][hashtable]$Meta,
        [hashtable]$ZipSection,
        [hashtable]$KeychainSection
    )
$lines = New-Object System.Collections.Generic.List[string]
$lines.Add(("=" * 78))
$lines.Add("GrayKey Hash Verification Report (ZIP + Keychain)")
$lines.Add("Tool: GrayKey Hash Verify v6.3")

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

    # Dictionary coming from C# Add-Type usually looks like a Hashtable in PS
    if ($sec -is [System.Collections.IDictionary] -and $sec.Contains($key)) {
        return [string]$sec[$key]
    }

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

    # --- Sections ---
    if ($ZipSection)     { Add-FileSection 'ZIP FILE'      $ZipSection }
    if ($KeychainSection){ Add-FileSection 'KEYCHAIN FILE' $KeychainSection }

    $lines.Add(('=' * 78))
    $lines.Add(('OVERALL RESULT: {0}' -f $Meta.OverallResult))
    $lines.Add(('=' * 78))

    # Ensure output directory exists
    $outDir = Split-Path -Parent $ReportPath
    if ($outDir -and -not (Test-Path -LiteralPath $outDir)) {
        New-Item -ItemType Directory -Force -Path $outDir | Out-Null
    }

    # Write report (UTF-8) 
    [System.IO.File]::WriteAllLines($ReportPath, $lines.ToArray(), [System.Text.Encoding]::UTF8)
}

# ---------------- Path normalization + drop routing (NEW) ----------------
function Normalize-InputPath {
    param([string]$Path)

    if ([string]::IsNullOrWhiteSpace($Path)) { return "" }

    $p = $Path

    # Convert to string, then trim outer whitespace
    $p = ([string]$p).Trim()

    # Remove wrapping quotes
    $p = $p.Trim('"')

    # Remove wrapping angle brackets
    if ($p.StartsWith("<") -and $p.EndsWith(">")) {
        $p = $p.Substring(1, $p.Length - 2).Trim()
    }

    # Remove ALL control/format/non-printing chars anywhere (includes CR/LF/TAB/zero-width/LRM/RLM)
    $p = [regex]::Replace($p, '\p{C}', '')

    # Final trim
    return $p.Trim()
}


function Get-IllegalPathCharsReport {
    param([string]$p)

    if ([string]::IsNullOrWhiteSpace($p)) { return "Path is empty." }

    $bad = @()

    foreach ($ch in $p.ToCharArray()) {
        $code = [int][char]$ch

        # Flag anything that is not printable ASCII-ish (control/format)
        if ($ch -match '\p{C}') {
            $bad += ("U+{0:X4} (Unicode category C)" -f $code)
            continue
        }

        # Flag invalid path chars
        if ([System.IO.Path]::GetInvalidPathChars() -contains $ch) {
            $bad += ("U+{0:X4} (InvalidPathChar '{1}')" -f $code, $ch)
        }
    }

    if ($bad.Count -eq 0) { return "No illegal chars detected." }

    return "Illegal/invisible characters found:`r`n" + ($bad -join "`r`n")
}


function Set-PathIfValid {
    param([System.Windows.Forms.TextBox]$Box, [string]$Path)

    try {
        $p = Normalize-InputPath -Path $Path
        if ([string]::IsNullOrWhiteSpace($p)) { return $false }
        if (-not (Test-Path -LiteralPath $p)) { return $false }

        $Box.Text = $p
        return $true
    }
    catch {
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Invalid Path", "OK", "Error") | Out-Null
        return $false
    }
}

# identify ZIP vs "keychain-ish" by extension
function Get-FileRole {
    param([string]$Path)

    $ext = ([string][System.IO.Path]::GetExtension($Path)).ToLowerInvariant()

    if ($ext -eq ".zip") { return "zip" }

    # GrayKey exports vary; allow common keychain-ish extensions
    if ($ext -in @(".keychain", ".keychain-db", ".kc", ".db", ".sqlite", ".sqlite3")) { return "kc" }

    # If it literally contains "keychain" in name, treat as keychain
    if ([System.IO.Path]::GetFileName($Path).ToLowerInvariant().Contains("keychain")) { return "kc" }

    return "unknown"
}

function Apply-DroppedFiles {
    param(
        [Parameter(Mandatory=$true)][string[]]$Files,
        [Parameter(Mandatory=$true)][object]$DroppedOnBox,
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$ZipBox,
        [Parameter(Mandatory=$true)][System.Windows.Forms.TextBox]$KcBox
    )

    # Normalize DroppedOnBox to an actual TextBox if possible
    $targetBox = $null
    if ($DroppedOnBox -is [System.Windows.Forms.TextBox]) {
        $targetBox = $DroppedOnBox
    } elseif ($DroppedOnBox -is [System.Windows.Forms.Control] -and $DroppedOnBox.PSObject.Properties.Match('Text').Count -gt 0) {
        $targetBox = $DroppedOnBox
    }

    foreach ($f in $Files) {
        $p = Normalize-InputPath -Path ([string]$f)
        if ([string]::IsNullOrWhiteSpace($p)) { continue }

        switch -Regex ($p.ToLowerInvariant()) {
            '\.zip$' {
                $ZipBox.Text = $p
                continue
            }

            # tweak this list if your keychain extension is different
            '\.(keychain|keychain-db|db|sqlite|plist)$' {
                $KcBox.Text = $p
                continue
            }

            default {
                if ($targetBox -and $targetBox.PSObject.Properties.Match('Text').Count -gt 0) {
                    $targetBox.Text = $p
                }
            }
        }
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


function Set-ChipState {
    param(
        [Parameter(Mandatory=$true)][string]$Text,
        [Parameter(Mandatory=$true)][int[]]$Rgb
    )

    if ($script:lblChip) {
        $script:lblChip.Text = $Text
        $script:lblChip.BackColor = [System.Drawing.Color]::FromArgb($Rgb[0], $Rgb[1], $Rgb[2])
    }
}

# ---------------- UI ----------------
$form = New-Object System.Windows.Forms.Form
# ===== App Branding / Header (paste AFTER: $form = New-Object System.Windows.Forms.Form) =====
$AppName    = "GrayKey Hash Verify"
$AppVersion = "6.2"
$AppOwner   = "Curtis Reha"
$BuildStamp = (Get-Date).ToString("yyyy-MM-dd")

# Title bar + subtle background
$form.Text      = "$AppName (ZIP + Keychain) - v$AppVersion"
$form.BackColor = [System.Drawing.Color]::FromArgb(245,245,245)

# ASCII banner (monospace)
$lblBanner = New-Object System.Windows.Forms.Label
$lblBanner.AutoSize  = $true
$lblBanner.Font      = New-Object System.Drawing.Font("Cascadia Mono", 10, [System.Drawing.FontStyle]::Bold)
$lblBanner.ForeColor = [System.Drawing.Color]::FromArgb(20,20,20)
$lblBanner.Text = @"
[$($AppName.ToUpper())]  v$AppVersion
> HASH  |  VERIFY  |  REPORT
"@
$lblBanner.Location = New-Object System.Drawing.Point(12, 10)
$form.Controls.Add($lblBanner)

# "Status chip" - READY
$script:lblChip = New-Object System.Windows.Forms.Label
$script:lblChip.AutoSize  = $true
$script:lblChip.Font      = New-Object System.Drawing.Font("Segoe UI", 8, [System.Drawing.FontStyle]::Bold)
$script:lblChip.BackColor = [System.Drawing.Color]::FromArgb(25, 135, 84)
$script:lblChip.ForeColor = [System.Drawing.Color]::White
$script:lblChip.Padding   = New-Object System.Windows.Forms.Padding(8,3,8,3)
$script:lblChip.Text      = "READY"
$script:lblChip.Location  = New-Object System.Drawing.Point(420, 14)
$form.Controls.Add($script:lblChip)


# About/build line
$lblAbout = New-Object System.Windows.Forms.Label
$lblAbout.AutoSize  = $true
$lblAbout.Font      = New-Object System.Drawing.Font("Segoe UI", 8)
$lblAbout.ForeColor = [System.Drawing.Color]::DimGray
$lblAbout.Text = "$AppName  $BuildStamp  |  $AppOwner"
$lblAbout.Location  = New-Object System.Drawing.Point(14, 54)
$form.Controls.Add($lblAbout)

# Header height so we can push the top group down safely
$HeaderYOffset = 70
# ===== End Header =====

$form.Text = "GrayKey Hash Verify (ZIP + Keychain) - v6.2"
$form.Size = New-Object System.Drawing.Size(920, 900)
$form.StartPosition = "CenterScreen"
$form.MaximizeBox = $false
$form.FormBorderStyle = "FixedDialog"

try {
    # In PS2EXE builds, $PSCommandPath may be empty/invalid. Prefer the running EXE path.
    $selfPath = [System.Diagnostics.Process]::GetCurrentProcess().MainModule.FileName

    if (-not [string]::IsNullOrWhiteSpace($selfPath) -and (Test-Path -LiteralPath $selfPath -PathType Leaf)) {
        $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($selfPath)
    }
    elseif (-not [string]::IsNullOrWhiteSpace($PSCommandPath) -and (Test-Path -LiteralPath $PSCommandPath -PathType Leaf)) {
        $form.Icon = [System.Drawing.Icon]::ExtractAssociatedIcon($PSCommandPath)
    }
} catch {
    # Do nothing: icon is cosmetic; never crash the app for this.
}


$openFile = New-Object System.Windows.Forms.OpenFileDialog
$openFile.Title = "Select file"
$openFile.Filter = "All files (*.*)|*.*"

$grpFiles = New-Object System.Windows.Forms.GroupBox
$grpFiles.Text = "Files to Verify (drag-and-drop; you can drop ZIP + Keychain together)"
$grpFiles.Location = New-Object System.Drawing.Point(12, 80)
$grpFiles.Size = New-Object System.Drawing.Size(880, 140)
$form.Controls.Add($grpFiles)

# --- ZIP + Keychain rows (pixel-perfect alignment) ---
$Left   = 12
$LabelW = 90          # <-- key fix: wide enough for "Keychain:"
$Gap    = 8
$BtnW   = 90
$BtnH   = 26
$RowH   = 26

$txtX = $Left + $LabelW + $Gap
$btnX = 770           # keep your existing right edge inside the group
$txtW = $btnX - $txtX - 10

# ZIP row
$lblZip = New-Object System.Windows.Forms.Label
$lblZip.Text = "ZIP:"
$lblZip.Location = New-Object System.Drawing.Point($Left, 30)
$lblZip.AutoSize = $false
$lblZip.Size = New-Object System.Drawing.Size($LabelW, 22)
$lblZip.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$grpFiles.Controls.Add($lblZip)

$txtZip = New-Object System.Windows.Forms.TextBox
$txtZip.Location = New-Object System.Drawing.Point($txtX, 27)
$txtZip.Size = New-Object System.Drawing.Size($txtW, 22)
$txtZip.ReadOnly = $true
$txtZip.AllowDrop = $true
$grpFiles.Controls.Add($txtZip)

$btnZip = New-Object System.Windows.Forms.Button
$btnZip.Text = "Browse..."
$btnZip.Location = New-Object System.Drawing.Point($btnX, 25)
$btnZip.Size = New-Object System.Drawing.Size($BtnW, $BtnH)   # <-- DO NOT let this get huge
$grpFiles.Controls.Add($btnZip)

# Keychain row
$lblKC = New-Object System.Windows.Forms.Label
$lblKC.Text = "Keychain:"
$lblKC.Location = New-Object System.Drawing.Point($Left, 73)
$lblKC.AutoSize = $false
$lblKC.Size = New-Object System.Drawing.Size($LabelW, 22)     # <-- key fix
$lblKC.TextAlign = [System.Drawing.ContentAlignment]::MiddleLeft
$grpFiles.Controls.Add($lblKC)

$txtKC = New-Object System.Windows.Forms.TextBox
$txtKC.Location = New-Object System.Drawing.Point($txtX, 70)
$txtKC.Size = New-Object System.Drawing.Size($txtW, 22)
$txtKC.ReadOnly = $true
$txtKC.AllowDrop = $true
$grpFiles.Controls.Add($txtKC)

$btnKC = New-Object System.Windows.Forms.Button
$btnKC.Text = "Browse..."
$btnKC.Location = New-Object System.Drawing.Point($btnX, 68)
$btnKC.Size = New-Object System.Drawing.Size($BtnW, $BtnH)
$grpFiles.Controls.Add($btnKC)
# --- end ZIP + Keychain rows ---


$grpMeta = New-Object System.Windows.Forms.GroupBox
$grpMeta.Text = "Optional Metadata (written to report header)"
$grpMeta.Location = New-Object System.Drawing.Point(12, 145)
$grpMeta.Size = New-Object System.Drawing.Size(880, 85)
$form.Controls.Add($grpMeta)

$lblCase = New-Object System.Windows.Forms.Label
$lblCase.Text = "Case #:"
$lblCase.Location = New-Object System.Drawing.Point(12, 34)
$lblCase.AutoSize = $true
$grpMeta.Controls.Add($lblCase)

$txtCase = New-Object System.Windows.Forms.TextBox
$txtCase.Location = New-Object System.Drawing.Point(70, 31)
$txtCase.Size = New-Object System.Drawing.Size(220, 22)
$grpMeta.Controls.Add($txtCase)

$lblItem = New-Object System.Windows.Forms.Label
$lblItem.Text = "Item #:"
$lblItem.Location = New-Object System.Drawing.Point(310, 34)
$lblItem.AutoSize = $true
$grpMeta.Controls.Add($lblItem)

$txtItem = New-Object System.Windows.Forms.TextBox
$txtItem.Location = New-Object System.Drawing.Point(365, 31)
$txtItem.Size = New-Object System.Drawing.Size(170, 22)
$grpMeta.Controls.Add($txtItem)

$lblExam = New-Object System.Windows.Forms.Label
$lblExam.Text = "Examiner:"
$lblExam.Location = New-Object System.Drawing.Point(555, 34)
$lblExam.AutoSize = $true
$grpMeta.Controls.Add($lblExam)

$txtExam = New-Object System.Windows.Forms.TextBox
$txtExam.Location = New-Object System.Drawing.Point(625, 31)
$txtExam.Size = New-Object System.Drawing.Size(235, 22)
$grpMeta.Controls.Add($txtExam)

$grpExp = New-Object System.Windows.Forms.GroupBox
$grpExp.Text = "Expected Hashes (SHA-256 first, then MD5)"
$grpExp.Location = New-Object System.Drawing.Point(12, 240)
$grpExp.Size = New-Object System.Drawing.Size(880, 210)
$form.Controls.Add($grpExp)
# Reflow downstream groups (prevents overlap)
$grpMeta.Location = New-Object System.Drawing.Point(12, ($grpFiles.Bottom + 10))
$grpExp.Location  = New-Object System.Drawing.Point(12, ($grpMeta.Bottom + 10))


$lblZipSHA = New-Object System.Windows.Forms.Label
$lblZipSHA.Text = "ZIP SHA-256:"
$lblZipSHA.Location = New-Object System.Drawing.Point(12, 35)
$lblZipSHA.AutoSize = $true
$grpExp.Controls.Add($lblZipSHA)

$txtZipSHA = New-Object System.Windows.Forms.TextBox
$txtZipSHA.Location = New-Object System.Drawing.Point(110, 32)
$txtZipSHA.Size = New-Object System.Drawing.Size(750, 22)
$grpExp.Controls.Add($txtZipSHA)

$lblZipMD5 = New-Object System.Windows.Forms.Label
$lblZipMD5.Text = "ZIP MD5:"
$lblZipMD5.Location = New-Object System.Drawing.Point(12, 65)
$lblZipMD5.AutoSize = $true
$grpExp.Controls.Add($lblZipMD5)

$txtZipMD5 = New-Object System.Windows.Forms.TextBox
$txtZipMD5.Location = New-Object System.Drawing.Point(110, 62)
$txtZipMD5.Size = New-Object System.Drawing.Size(750, 22)
$grpExp.Controls.Add($txtZipMD5)

$lblKCSHA = New-Object System.Windows.Forms.Label
$lblKCSHA.Text = "KC SHA-256:"
$lblKCSHA.Location = New-Object System.Drawing.Point(12, 120)
$lblKCSHA.AutoSize = $true
$grpExp.Controls.Add($lblKCSHA)

$txtKCSHA = New-Object System.Windows.Forms.TextBox
$txtKCSHA.Location = New-Object System.Drawing.Point(110, 117)
$txtKCSHA.Size = New-Object System.Drawing.Size(750, 22)
$grpExp.Controls.Add($txtKCSHA)

$lblKCMD5 = New-Object System.Windows.Forms.Label
$lblKCMD5.Text = "KC MD5:"
$lblKCMD5.Location = New-Object System.Drawing.Point(12, 150)
$lblKCMD5.AutoSize = $true
$grpExp.Controls.Add($lblKCMD5)

$txtKCMD5 = New-Object System.Windows.Forms.TextBox
$txtKCMD5.Location = New-Object System.Drawing.Point(110, 147)
$txtKCMD5.Size = New-Object System.Drawing.Size(750, 22)
$grpExp.Controls.Add($txtKCMD5)

# --- Button row placed dynamically under Expected Hashes group ---
$btnY = $grpExp.Bottom + 12

$btnRun = New-Object System.Windows.Forms.Button
$btnRun.Text = "Compute + Verify + Save Combined Report"
$btnRun.Location = New-Object System.Drawing.Point(12, $btnY)
$btnRun.Size = New-Object System.Drawing.Size(360, 36)
$form.Controls.Add($btnRun)

$btnSaveAs = New-Object System.Windows.Forms.Button
$btnSaveAs.Text = "Save As..."
$btnSaveAs.Location = New-Object System.Drawing.Point(($btnRun.Right + 10), $btnY)
$btnSaveAs.Size = New-Object System.Drawing.Size(120, 36)
$btnSaveAs.Enabled = $false
$form.Controls.Add($btnSaveAs)

$btnCancel = New-Object System.Windows.Forms.Button
$btnCancel.Text = "Cancel"
$btnCancel.Location = New-Object System.Drawing.Point(($btnSaveAs.Right + 10), $btnY)
$btnCancel.Size = New-Object System.Drawing.Size(100, 36)
$btnCancel.Enabled = $false
$form.Controls.Add($btnCancel)

$ButtonsBottom = $btnCancel.Bottom

# Status label
$lblStatus = New-Object System.Windows.Forms.Label
$lblStatus.Text = "Status: Select ZIP and/or Keychain."
$lblStatus.Location = New-Object System.Drawing.Point(12, ($ButtonsBottom + 12))
$lblStatus.AutoSize = $true
$form.Controls.Add($lblStatus)

# Progress bar
$progressBar = New-Object System.Windows.Forms.ProgressBar
$progressBar.Location = New-Object System.Drawing.Point(12, ($lblStatus.Bottom + 6))
$progressBar.Size     = New-Object System.Drawing.Size(780, 18)
$progressBar.Minimum = 0
$progressBar.Maximum = 100
$form.Controls.Add($progressBar)

# Progress text (GB readout)
$lblProgress = New-Object System.Windows.Forms.Label
$lblProgress.Location = New-Object System.Drawing.Point(($progressBar.Right + 10), $progressBar.Top)
$lblProgress.AutoSize = $true
$lblProgress.ForeColor = [System.Drawing.Color]::DimGray
$form.Controls.Add($lblProgress)

# Output box
$txtOutput = New-Object System.Windows.Forms.TextBox
$txtOutput.Multiline = $true
$txtOutput.ScrollBars = "Vertical"
$txtOutput.ReadOnly = $true
$txtOutput.Font = New-Object System.Drawing.Font("Consolas", 10)
$txtOutput.Location = New-Object System.Drawing.Point(12, ($progressBar.Bottom + 10))
$txtOutput.Size     = New-Object System.Drawing.Size(880, 260)
$form.Controls.Add($txtOutput)

# Make window tall enough so nothing is cut off
$form.ClientSize = New-Object System.Drawing.Size(920, ($txtOutput.Bottom + 20))


$saveFile = New-Object System.Windows.Forms.SaveFileDialog
$saveFile.Title = "Save verification report"
$saveFile.Filter = "Text file (*.txt)|*.txt"
$saveFile.OverwritePrompt = $true

# enable multi-file drop
Enable-DropToBox -Box $txtZip -ZipBox $txtZip -KcBox $txtKC
Enable-DropToBox -Box $txtKC  -ZipBox $txtZip -KcBox $txtKC

$btnZip.Add_Click({
    if ($openFile.ShowDialog() -eq "OK") {
        [void](Set-PathIfValid -Box $txtZip -Path $openFile.FileName)
    }
})
$btnKC.Add_Click({
    if ($openFile.ShowDialog() -eq "OK") {
        [void](Set-PathIfValid -Box $txtKC -Path $openFile.FileName)
    }
})

# BackgroundWorker wiring (C# DoWork delegate)
$worker = New-Object System.ComponentModel.BackgroundWorker
$worker.WorkerReportsProgress = $true
$worker.WorkerSupportsCancellation = $true

$hashWorker = New-Object HashWorker
$mi = $hashWorker.GetType().GetMethod("DoWork")
$del = [System.Delegate]::CreateDelegate([System.ComponentModel.DoWorkEventHandler], $hashWorker, $mi)
$worker.add_DoWork($del)

$lastMeta = $null
$lastZipSection = $null
$lastKCSection = $null
$lastDefaultReportPath = $null

$worker.Add_ProgressChanged({
    param($sender, $e)
    $progressBar.Value = $e.ProgressPercentage
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

    # Treat cancellation exceptions as a normal cancel (not an error)
    $msg = $e.Error.ToString()
    if ($e.Error -is [System.OperationCanceledException] -or $msg -match 'OperationCanceledException') {

        Set-ChipState -Text "CANCELLED" -Rgb @(108,117,125)   # gray
        $lblStatus.Text = "Status: Cancelled"
        $txtOutput.Text = "Cancelled by user."
        return
    }

    # Real errors
    Set-ChipState -Text "FAILED" -Rgb @(220,53,69)           # red
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
    $lastDefaultReportPath = Build-DefaultReportPath -BaseDir $baseDir -CaseNumber $meta.CaseNumber -ItemNumber $meta.ItemNumber

    Write-CombinedReport -ReportPath $lastDefaultReportPath -Meta $meta -ZipSection $zipSection -KeychainSection $kcSection

    $summary = @()
    if ($zipSection) { $summary += "ZIP Result: $($zipSection.FileOverall)" }
    if ($kcSection)  { $summary += "Keychain Result: $($kcSection.FileOverall)" }
    $summary += "OVERALL: $overall"
    $summary += "REPORT SAVED: $lastDefaultReportPath"

    $txtOutput.Text = ($summary -join "`r`n")
	Set-ChipState -Text "COMPLETE" -Rgb @(25,135,84)
    $lblStatus.Text = "Status: Done. Overall = $overall"
    $btnSaveAs.Enabled = $true

    $lastMeta = $meta
    $lastZipSection = $zipSection
    $lastKCSection = $kcSection
})

$btnCancel.Add_Click({
    if ($worker.IsBusy) {
        $btnCancel.Enabled = $false
        $lblStatus.Text = "Status: Cancelling..."
        $worker.CancelAsync()
    }
})

$btnRun.Add_Click({
    try {
        # Defense-in-depth: normalize again right before hashing
        $zipPath = Normalize-InputPath -Path $txtZip.Text
        $kcPath  = Normalize-InputPath -Path $txtKC.Text
		$txtZip.Text = $zipPath
		$txtKC.Text  = $kcPath

# Detect invisible/illegal characters before we pass to C#
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

if (-not [string]::IsNullOrWhiteSpace($zipPath) -and 
    -not (Test-Path -LiteralPath $zipPath -PathType Leaf)) {
    throw "ZIP file not found: <$zipPath>"
}

if (-not [string]::IsNullOrWhiteSpace($kcPath) -and 
    -not (Test-Path -LiteralPath $kcPath -PathType Leaf)) {
    throw "Keychain file not found: <$kcPath>"
}
if ([string]::IsNullOrWhiteSpace($zipPath) -and 
    [string]::IsNullOrWhiteSpace($kcPath)) {

    [System.Windows.Forms.MessageBox]::Show(
        "Select at least one file (ZIP and/or Keychain).",
        "Missing Files",
        "OK",
        "Warning"
    ) | Out-Null

    return
}


        # Update UI with normalized values (so EXE/PS1 behavior matches)
$txtZip.Text = $zipPath
$txtKC.Text  = $kcPath

        $btnRun.Enabled = $false
$btnSaveAs.Enabled = $false
$btnCancel.Enabled = $true
Set-ChipState -Text "RUNNING" -Rgb @(13, 110, 253)   # blue

$progressBar.Value = 0

        $progressBar.Value = 0
        $lblProgress.Text = ""
        $txtOutput.Clear()
        $lblStatus.Text = "Status: Starting..."
        $form.Refresh()

        $job = New-Object HashJobArgs
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
        Set-ChipState -Text "FAILED" -Rgb @(220, 53, 69)     # red
        [System.Windows.Forms.MessageBox]::Show($_.Exception.Message, "Run Failed", "OK", "Error") | Out-Null
        $btnRun.Enabled = $true
        $btnSaveAs.Enabled = $false
        $btnCancel.Enabled = $false
        $lblStatus.Text = "Status: ERROR"
        $txtOutput.Text = "ERROR:`r`n$($_.Exception.ToString())"
    }
})

$btnSaveAs.Add_Click({
    if (-not $lastMeta -or -not $lastDefaultReportPath) { return }
    $saveFile.FileName = Split-Path -Leaf $lastDefaultReportPath
    $saveFile.InitialDirectory = Split-Path -Parent $lastDefaultReportPath

    if ($saveFile.ShowDialog() -eq "OK") {
        Write-CombinedReport -ReportPath $saveFile.FileName -Meta $lastMeta -ZipSection $lastZipSection -KeychainSection $lastKCSection
        [System.Windows.Forms.MessageBox]::Show("Saved:`n$($saveFile.FileName)", "Saved", "OK", "Information") | Out-Null
    }
})

[void]$form.ShowDialog()