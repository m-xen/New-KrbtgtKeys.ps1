
# Scheduling

The script Schedule-KrbtgtKeys.ps1 should be scheduled to run using Task Scheduler on a Domain joined system.

The file "Krbtgt Password Reset.xml" is an example scheduled task, set to run every 3 months, as domain admin with "Run with highest privileges" set.

    *Ensure the <WorkingDirectory>C:\New-KrbtgtKeys.ps1-master</WorkingDirectory> is set appropriately (to a writeable directory), if this is not set or is set to a restricted directory, the script will fail, e.g., if left blank then the log file may fail to be created in "C:\Windows\System32\WindowsPowerShell\v1.0\" without UAC elevation.

    *Also, as with all scheduled tasks, ensure the Working Directory path *does not* have quotation marks "" or the task will fail to launch\start, with "Error Value: 2147942667".