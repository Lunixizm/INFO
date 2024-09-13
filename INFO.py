import subprocess

# PowerShell script as a Python string
ps_script = """

# General Information
$outputFile = "C:\\Temp\\general_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== GENERAL INFORMATION ===" | Out-File -FilePath $outputFile
Get-ComputerInfo | Out-File -FilePath $outputFile -Append

# Memory (RAM) Information
$outputFile = "C:\\Temp\\memory_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== MEMORY (RAM) INFORMATION ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_PhysicalMemory | Out-File -FilePath $outputFile -Append

# Disk and Storage Information
$outputFile = "C:\\Temp\\disk_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== DISK AND STORAGE INFORMATION ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_DiskDrive | Out-File -FilePath $outputFile -Append
Get-WmiObject -Class Win32_LogicalDisk | Out-File -FilePath $outputFile -Append

# Operating System Information
$outputFile = "C:\\Temp\\os_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== OPERATING SYSTEM INFORMATION ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_OperatingSystem | Out-File -FilePath $outputFile -Append

# Network Information (IP, Gateway, DNS)
$outputFile = "C:\\Temp\\network_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== NETWORK INFORMATION ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_NetworkAdapterConfiguration -Filter "IPEnabled = True" | Select-Object IPAddress, DefaultIPGateway, DNSServerSearchOrder | Out-File -FilePath $outputFile -Append

# Installed Programs
$outputFile = "C:\\Temp\\installed_programs.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED PROGRAMS ===" | Out-File -FilePath $outputFile
Get-ItemProperty HKLM:\\Software\\Microsoft\\Windows\\CurrentVersion\\Uninstall\\* | Select-Object DisplayName, DisplayVersion, Publisher, InstallDate | Out-File -FilePath $outputFile -Append

# Running Processes
$outputFile = "C:\\Temp\\running_processes.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== RUNNING PROCESSES ===" | Out-File -FilePath $outputFile
Get-Process | Out-File -FilePath $outputFile -Append

# Startup Programs
$outputFile = "C:\\Temp\\startup_programs.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== STARTUP PROGRAMS ===" | Out-File -FilePath $outputFile
Get-CimInstance -ClassName Win32_StartupCommand | Out-File -FilePath $outputFile -Append

# Open TCP Connections
$outputFile = "C:\\Temp\\opened_tcp.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== OPEN TCP CONNECTIONS ===" | Out-File -FilePath $outputFile
Get-NetTCPConnection | Out-File -FilePath $outputFile -Append

# Network Interfaces
$outputFile = "C:\\Temp\\network_interfaces.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== NETWORK INTERFACES ===" | Out-File -FilePath $outputFile
Get-NetAdapter | Out-File -FilePath $outputFile -Append

# User Accounts
$outputFile = "C:\\Temp\\user_accounts.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== USER ACCOUNTS ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_UserAccount | Out-File -FilePath $outputFile -Append

# Installed Drivers
$outputFile = "C:\\Temp\\installed_drivers.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED DRIVERS ===" | Out-File -FilePath $outputFile
Get-WmiObject Win32_PnPSignedDriver | Out-File -FilePath $outputFile -Append

# Security Software (Antivirus and Firewall)
$outputFile = "C:\\Temp\\security_software.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED SECURITY SOFTWARE ===" | Out-File -FilePath $outputFile
Get-WmiObject -Namespace root/SecurityCenter2 -Class AntiVirusProduct | Out-File -FilePath $outputFile -Append
Get-NetFirewallProfile | Out-File -FilePath $outputFile -Append

# Hardware Information
$outputFile = "C:\\Temp\\hardware_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== HARDWARE INFORMATION ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_ComputerSystem | Out-File -FilePath $outputFile -Append

# Browsers and Addons
$outputFile = "C:\\Temp\\browsers_addons.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED BROWSERS AND ADDONS ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_BrowserHelperObject | Out-File -FilePath $outputFile -Append

# Scheduled Tasks
$outputFile = "C:\\Temp\\scheduled_tasks.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== SCHEDULED TASKS ===" | Out-File -FilePath $outputFile
Get-ScheduledTask | Out-File -FilePath $outputFile -Append

# Installed Printers
$outputFile = "C:\\Temp\\installed_printers.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED PRINTERS ===" | Out-File -FilePath $outputFile
Get-Printer | Out-File -FilePath $outputFile -Append

# Power Plans
$outputFile = "C:\\Temp\\power_plans.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== POWER PLANS ===" | Out-File -FilePath $outputFile
powercfg /list | Out-File -FilePath $outputFile -Append

# Installed Hotfixes
$outputFile = "C:\\Temp\\installed_hotfixes.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED HOTFIXES ===" | Out-File -FilePath $outputFile
Get-HotFix | Out-File -FilePath $outputFile -Append

# Services (Installed and Running)
$outputFile = "C:\\Temp\\services_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED AND RUNNING SERVICES ===" | Out-File -FilePath $outputFile
Get-Service | Out-File -FilePath $outputFile -Append

# Installed Certificates
$outputFile = "C:\\Temp\\installed_certificates.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED CERTIFICATES ===" | Out-File -FilePath $outputFile
Get-ChildItem -Path Cert:\\LocalMachine\\My | Out-File -FilePath $outputFile -Append

# Installed Fonts
$outputFile = "C:\\Temp\\installed_fonts.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED FONTS ===" | Out-File -FilePath $outputFile
Get-WmiObject -Query "SELECT * FROM Win32_FontInfoAction" | Out-File -FilePath $outputFile -Append

# Last 24 Hours Event Logs
$outputFile = "C:\\Temp\\event_logs.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== LAST 24 HOURS EVENT LOGS ===" | Out-File -FilePath $outputFile
Get-EventLog -LogName System -After (Get-Date).AddDays(-1) | Out-File -FilePath $outputFile -Append

# Open Ports
$outputFile = "C:\\Temp\\open_ports.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== OPEN PORTS ===" | Out-File -FilePath $outputFile
netstat -an | Select-String "LISTENING" | Out-File -FilePath $outputFile -Append

# Installed Disk Drivers
$outputFile = "C:\\Temp\\disk_drivers.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== INSTALLED DISK DRIVERS ===" | Out-File -FilePath $outputFile
Get-WmiObject Win32_DiskDrive | Out-File -FilePath $outputFile -Append

# Network Traffic and Statistics
$outputFile = "C:\\Temp\\network_traffic.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== NETWORK TRAFFIC AND STATISTICS ===" | Out-File -FilePath $outputFile
Get-NetAdapterStatistics | Out-File -FilePath $outputFile -Append

# CPU Information
$outputFile = "C:\\Temp\\cpu_info.txt"
if (-not (Test-Path $outputFile)) { New-Item -Path $outputFile -ItemType File -Force }
"=== CPU INFORMATION ===" | Out-File -FilePath $outputFile
Get-WmiObject -Class Win32_Processor | Out-File -FilePath $outputFile -Append

"""

# Run the PowerShell script
def run_powershell_script(script):
    command = ["powershell", "-Command", script]
    subprocess.run(command, check=True)

# Execute the PowerShell script
run_powershell_script(ps_script)
