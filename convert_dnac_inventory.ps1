<#
.SYNOPSIS
    Processes a Cisco Catalyst Center inventory CSV file to add a Flash Size column.

.DESCRIPTION
    This script takes a Cisco Catalyst Center inventory CSV as input, adds a 'Flash Size (MB)'
    column based on the 'Part No.' field, and outputs a new CSV file.
    
    Supports drag-and-drop: Just drag a CSV file onto this .ps1 file.
    Handles multiple part numbers in a single cell, matching flash sizes for each part.

.NOTES
    To enable drag-and-drop functionality:
    1. Right-click this .ps1 file and select "Properties"
    2. Click "Unblock" if available, then "Apply"
    3. Right-click the file again, and select "Run with PowerShell"
    4. If prompted, select "Yes" to allow running
    
    After doing this once, you should be able to drag files onto the script.
#>

# Define flash size mapping for different part numbers
$flashSizeMapping = @{
    # Exact model matches - use these first
    "C9300-24T"       = 11353
    "C9300-24U"       = 11353
    "C9300-48F-E" = 11353
    "C9300-48U"       = 11353
    "C9300-48UXM"    = 11353
    "WS-C3650-24PD-E" = 1621
    "WS-3650-48FD-E" =  1562 
    "WS-C3850-24XS-E" = 1680
    "WS-C3850-24S-E"  = 1680
    "WS-C3850-12S-E"  = 1562
    "WS-C3850-12XS-E" = 1680
    "WS-C3850-12X48U-S" = 1680
    "WS-C3850-12X48U-E" = 1680
    "WS-C3850-48F-E" = 1680
    "N3K-C3172PQ-10GBE" = 1821
    "C8300-1N1S-6T" = 7693
    "Cisco Firepower 2110" = 10000
    "CISCO3925-CHASSIS" = 514
    "ISR4451-X/K9" = 15155
    # Partial/series matches - used as fallbacks, and marked with "*" for clarity
    "C9300"           = 11353  # Match any C9300 series
    "3850"            = 1680   # Match any 3850 series
    "3650"            = 1621   # Match any 3650 series
}

# Function to get flash size for a part number
function Get-FlashSize {
    param (
        [string]$partNo
    )
    
    $partNo = $partNo.Trim()
    
    # Try exact match first
    if ($flashSizeMapping.ContainsKey($partNo)) {
        return $flashSizeMapping[$partNo]
    }
    
    # Then try partial matches
    foreach ($key in $flashSizeMapping.Keys) {
        if ($partNo -match $key) {
            return $flashSizeMapping[$key]
        }
    }
    
    # No match found
    return ""
}

# Get input file - support both drag-drop and manual execution
$InputFile = $null

# Check for drag-and-drop (file passed as argument)
if ($args.Count -gt 0) {
    $InputFile = $args[0].ToString().Trim('"')
    
    # Verify the file exists
    if (-not (Test-Path -Path $InputFile -PathType Leaf)) {
        Write-Error "File not found: $InputFile"
        $InputFile = $null
    }
}

# If no valid input file, prompt user
if (-not $InputFile) {
    Write-Host "Drag a CSV file onto this window and press Enter:" -ForegroundColor Cyan
    $InputFile = Read-Host
    $InputFile = $InputFile.Trim('"', "'") # Remove quotes if present
    
    # Verify the file exists
    if (-not (Test-Path -Path $InputFile -PathType Leaf)) {
        Write-Error "File not found: $InputFile"
        Write-Host "Press any key to exit..."
        $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
        exit 1
    }
}

# Only process CSV files
if (-not $InputFile.EndsWith(".csv", [StringComparison]::OrdinalIgnoreCase)) {
    Write-Error "Only CSV files are supported. File must have .csv extension."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Set output file to be in the same directory as the script
$ScriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
$OutputFile = Join-Path -Path $ScriptDir -ChildPath ([System.IO.Path]::GetFileNameWithoutExtension($InputFile) + "_processed.csv")

Write-Host "Processing $InputFile..." -ForegroundColor Green

# Read the CSV file contents
try {
    $content = Get-Content -Path $InputFile -Raw -ErrorAction Stop
}
catch {
    Write-Error "Failed to read file: $_"
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# This function will respect quoted fields with commas inside them
function ConvertFrom-CsvLine {
    param (
        [string]$line
    )
    
    $result = @()
    $current = ""
    $inQuotes = $false
    
    for ($i = 0; $i -lt $line.Length; $i++) {
        $char = $line[$i]
        
        if ($char -eq '"') {
            $inQuotes = -not $inQuotes
        }
        elseif ($char -eq ',' -and -not $inQuotes) {
            $result += $current
            $current = ""
        }
        else {
            $current += $char
        }
    }
    
    # Add the last field
    $result += $current
    
    return $result
}

# Split into lines and process
$lines = $content -split "`r`n|\r|\n"
$outputLines = @()

# Identify the header line
$headerLineIndex = -1
$partNoColumnIndex = -1

for ($i = 0; $i -lt $lines.Count; $i++) {
    if ($lines[$i] -match "Device Family,Device Type,Device Name,Serial No.") {
        $headerLineIndex = $i
        
        # Split the header line to find the Part No. column index
        $headerFields = ConvertFrom-CsvLine -line $lines[$i]
        for ($j = 0; $j -lt $headerFields.Count; $j++) {
            if ($headerFields[$j].Trim() -eq "Part No.") {
                $partNoColumnIndex = $j
                break
            }
        }
        
        break
    }
}

if ($headerLineIndex -eq -1 -or $partNoColumnIndex -eq -1) {
    Write-Error "Could not find the header line or Part No. column in the CSV file."
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

# Copy the preamble lines
for ($i = 0; $i -lt $headerLineIndex; $i++) {
    $outputLines += $lines[$i]
}

# Add the new column to the header
$headerFields = ConvertFrom-CsvLine -line $lines[$headerLineIndex]
$headerFields += "Flash Size (MB)"
$outputLines += $headerFields -join ","

# Process each data row
$devicesProcessed = 0
$flashSizesAdded = 0
$totalPartNumbers = 0

for ($i = $headerLineIndex + 1; $i -lt $lines.Count; $i++) {
    if ([string]::IsNullOrWhiteSpace($lines[$i])) {
        continue  # Skip empty lines
    }
    
    $devicesProcessed++
    $fields = ConvertFrom-CsvLine -line $lines[$i]
    
    # Ensure we have enough fields
    if ($fields.Count -le $partNoColumnIndex) {
        Write-Warning "Line $i has fewer fields than expected. Skipping."
        $outputLines += $lines[$i] + ","  # Add empty flash size
        continue
    }
    
    # Get the part number field
    $partNoField = $fields[$partNoColumnIndex].Trim('"', ' ')
    Write-Host "Processing line with part number(s): '$partNoField'" -ForegroundColor Gray
    
    # Check if there are multiple part numbers (common delimiters: comma, semicolon, space, newline)
    $partNumbers = @()
    
    # First try to split by common delimiters
    if ($partNoField -match ',|\||;|\n|\r|/') {
        # Split using multiple possible delimiters
        $partNumbers = $partNoField -split '[,\|;\r\n/]' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) } | ForEach-Object { $_.Trim() }
    }
    else {
        # Also check for multiple part numbers separated by spaces (if they follow the known patterns)
        $potentialParts = $partNoField -split '\s+' | Where-Object { -not [string]::IsNullOrWhiteSpace($_) }
        
        # Only consider space-delimited parts if they match known part number patterns
        # or if there are exactly two entries (this is a simple heuristic)
        $validParts = $potentialParts | Where-Object { 
            $_ -match '^(C9300|C\d{4}|WS-C\d{4}|Cisco)' -or 
            $_ -match '^\d{4}[A-Z]?' -or
            $potentialParts.Count -eq 2
        }
        
        if ($validParts.Count -gt 1) {
            $partNumbers = $validParts
        }
        else {
            # Just one part number
            $partNumbers = @($partNoField)
        }
    }
    
    $totalPartNumbers += $partNumbers.Count
    
    # Array to store flash sizes for all parts
    $flashSizes = @()
    $flashSizesFound = 0
    
    # Process each part number
    foreach ($partNo in $partNumbers) {
        Write-Host "  Checking part number: '$partNo'" -ForegroundColor Gray
        
        # Get flash size for this part number
        $flashSize = Get-FlashSize -partNo $partNo
        
        if (-not [string]::IsNullOrEmpty($flashSize)) {
            $flashSizes += $flashSize
            $flashSizesFound++
            Write-Host "    Found flash size: $flashSize MB" -ForegroundColor Green
        }
        else {
            Write-Host "    No match found for: $partNo" -ForegroundColor DarkYellow
        }
    }
    
    # Format flash sizes in the same order as part numbers
    $flashSizeOutput = if ($flashSizes.Count -gt 0) {
        $flashSizesAdded++
         '"' + ($flashSizes -join ", ") + '"'
    } else {
        ""
    }
    
    # Add the flash size to the row
    $outputLines += $lines[$i] + "," + $flashSizeOutput
}

# Write the output file
try {
    $outputLines | Out-File -FilePath $OutputFile -Encoding utf8 -ErrorAction Stop
    Write-Host "Processing complete!" -ForegroundColor Green
    Write-Host "Output saved to: $OutputFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Devices processed: $devicesProcessed" 
    Write-Host "  Total part numbers found: $totalPartNumbers"
    Write-Host "  Devices with flash sizes added: $flashSizesAdded"
}
catch {
    Write-Error "Failed to write output file: $_"
    Write-Host "Press any key to exit..."
    $null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
    exit 1
}

Write-Host ""
Write-Host "Flash Size Mappings Applied:" -ForegroundColor Cyan
foreach ($key in $flashSizeMapping.Keys | Sort-Object) {
    Write-Host "  $key = $($flashSizeMapping[$key]) MB"
}

# Instructions for adding more flash sizes in the future
Write-Host ""
Write-Host "To add additional flash sizes in the future:" -ForegroundColor Cyan
Write-Host "  1. Edit this script in Notepad or PowerShell ISE"
Write-Host "  2. Find the `$flashSizeMapping hashtable"
Write-Host "  3. Add new entries like: `$flashSizeMapping[`"NEW-PART-NUMBER`"] = 1234"
Write-Host "  4. Save the script"

# Keep console window open
Write-Host ""
Write-Host "Press any key to exit..." -ForegroundColor Yellow
$null = $Host.UI.RawUI.ReadKey("NoEcho,IncludeKeyDown")
