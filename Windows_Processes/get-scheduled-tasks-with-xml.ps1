
$tasks = Get-ScheduledTask
foreach ($task in $tasks) {
    try {
        $info = Get-ScheduledTaskInfo -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
        $definitionXml = Export-ScheduledTask -TaskName $task.TaskName -TaskPath $task.TaskPath -ErrorAction Stop
        # Get metat data from the raw XML
        $xml = [xml]$definitionXml
        $regInfo = $xml.Task.RegistrationInfo
        $author        = $regInfo.Author
        $date          = $regInfo.Date
        $description   = $regInfo.Description
        $documentation = $regInfo.Documentation
        $source        = $regInfo.Source
        $version       = $regInfo.Version
        $state         = $info.State
        $taskName      = $task.TaskName
        $taskPath      = $task.TaskPath
        # Since there are so many tasks, write a header
        Write-Output "/**************************************/"
        Write-Output " Author       : $author"
        Write-Output " Date         : $date"
        Write-Output " Description  : $description"
        Write-Output " Documentation: $documentation"
        Write-Output " Source       : $source"
        Write-Output " TaskName     : $taskName"
        Write-Output " TaskPath     : $taskPath"
        Write-Output " Version      : $version"
        Write-Output " State        : $state"
        Write-Output "/**************************************/"
        Write-Output ""

        # Convert XML to string. Advise if it is binary data.
        $xmlString = $xml.OuterXml
        if ($xmlString -match '[^\x09\x0A\x0D\x20-\x7E]') {
            $bytes = [System.Text.Encoding]::UTF8.GetBytes($xmlString)
            $sha256 = [System.BitConverter]::ToString((New-Object -TypeName System.Security.Cryptography.SHA256Managed).ComputeHash($bytes)) -replace '-', ''
            Write-Output "# Binary data found. SHA256 hash: $sha256"
        } else {
            # Pretty-print the XML
            $stringWriter = New-Object System.IO.StringWriter
            $xmlWriter = New-Object System.Xml.XmlTextWriter($stringWriter)
            $xmlWriter.Formatting = "Indented"
            $xml.WriteContentTo($xmlWriter)
            $xmlWriter.Flush()
            $stringWriter.ToString() | Write-Output
        }
        Write-Output ""
    } catch {
        Write-Warning "Cannot process task '$($task.TaskName)': $($_.Exception.Message)"
    }
} 

