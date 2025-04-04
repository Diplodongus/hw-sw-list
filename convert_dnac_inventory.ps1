<#
.SYNOPSIS
    Processes a Cisco Catalyst Center inventory CSV file to add a Flash Size column.

.DESCRIPTION
    This script takes a Cisco Catalyst Center inventory CSV as input, adds a 'Flash Size (MB)'
    column based on the 'Part No.' field, and outputs a new CSV file.
    
    Supports drag-and-drop: Just drag a CSV file onto this .ps1 file.

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
    "WS-C3850-24XS-E" = 1680
    "WS-C3650-24PD-E" = 1621
    
    # Partial/series matches - used as fallbacks, and marked with "*" for clarity
    #"C9300"           = "11353*"  # Match any C9300 series
    #"3850"            = "1680*"   # Match any 3850 series
    #"3650"            = "1621*"   # Match any 3650 series
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
        $headerFields = Parse-CsvLine -line $lines[$i]
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
$headerFields = Parse-CsvLine -line $lines[$headerLineIndex]
$headerFields += "Flash Size (MB)"
$outputLines += $headerFields -join ","

# Process each data row
$devicesProcessed = 0
$flashSizesAdded = 0

for ($i = $headerLineIndex + 1; $i -lt $lines.Count; $i++) {
    if ([string]::IsNullOrWhiteSpace($lines[$i])) {
        continue  # Skip empty lines
    }
    
    $devicesProcessed++
    $fields = Parse-CsvLine -line $lines[$i]
    
    # Ensure we have enough fields
    if ($fields.Count -le $partNoColumnIndex) {
        Write-Warning "Line $i has fewer fields than expected. Skipping."
        $outputLines += $lines[$i] + ","  # Add empty flash size
        continue
    }
    
    # Get the part number
    $partNo = $fields[$partNoColumnIndex].Trim('"', ' ')
    Write-Host "Checking part number: '$partNo'" -ForegroundColor Gray
    
    # Determine flash size based on part number
    $flashSize = ""
    
    # Try exact match first
    if ($flashSizeMapping.ContainsKey($partNo)) {
        $flashSize = $flashSizeMapping[$partNo]
        $flashSizesAdded++
        Write-Host "  Exact match found: $partNo = $flashSize MB" -ForegroundColor Green
    }
    # Then try to match part of the model number
    else {
        # Check each key in the mapping
        foreach ($key in $flashSizeMapping.Keys | Where-Object { $_ -notmatch "^\d" }) { # Skip numeric-only keys
            if ($partNo -match $key) {
                $flashSize = $flashSizeMapping[$key]
                $flashSizesAdded++
                Write-Host "  Pattern match found: $partNo matches pattern $key = $flashSize MB" -ForegroundColor Green
                break
            }
        }
        
        # If still no match, try the most generic matches
        if ([string]::IsNullOrEmpty($flashSize)) {
            # Look for series numbers in the part number
            if ($partNo -match "C?9300|93\d{2}") {
                $flashSize = $flashSizeMapping["C9300"]
                $flashSizesAdded++
                Write-Host "  Series match found: $partNo matches C9300 series = $flashSize MB" -ForegroundColor Green
            }
            elseif ($partNo -match "3850|38\d{2}") {
                $flashSize = $flashSizeMapping["3850"]
                $flashSizesAdded++
                Write-Host "  Series match found: $partNo matches 3850 series = $flashSize MB" -ForegroundColor Green
            }
            elseif ($partNo -match "3650|36\d{2}") {
                $flashSize = $flashSizeMapping["3650"]
                $flashSizesAdded++
                Write-Host "  Series match found: $partNo matches 3650 series = $flashSize MB" -ForegroundColor Green
            }
            else {
                Write-Host "  No match found for: $partNo" -ForegroundColor DarkYellow
            }
        }
    }
    
    # Add the flash size to the row
    $outputLines += $lines[$i] + "," + $flashSize
}

# Write the output file
try {
    $outputLines | Out-File -FilePath $OutputFile -Encoding utf8 -ErrorAction Stop
    Write-Host "Processing complete!" -ForegroundColor Green
    Write-Host "Output saved to: $OutputFile" -ForegroundColor Yellow
    Write-Host ""
    Write-Host "Summary:" -ForegroundColor Cyan
    Write-Host "  Devices processed: $devicesProcessed" 
    Write-Host "  Flash sizes added: $flashSizesAdded"
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