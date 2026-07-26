# PowerShell script to check HTTP/HTTPS response for BlueTeamHandbook.com
# and print consistent results to the screen.

$site = "BlueTeamHandbook.com"     
$protocols = @("http", "https")
foreach ($proto in $protocols) {
    $url = "${proto}://$site"
    try {
        $response = Invoke-WebRequest -Uri $url -UseBasicParsing -ErrorAction Stop
        if ($null -eq $response -or $response.StatusCode -ne 200) {
            $statusMessage = if ($null -eq $response) { "No response" 
        } else { $response.StatusDescription }
        Write-Output ("{0} | Protocol: {1} | Site: {2} | Status: {3}" -f ` 
           (Get-Date), $proto, $site, $statusMessage)
        } else {
            Write-Output ("{0} | Protocol: {1} | Site: {2} | Status: 200 OK" -f `
               (Get-Date), $proto, $site)
       }     
   }     
    catch {
        $statusMessage = $_.Exception.Message
        Write-Output ("{0} | Protocol: {1} | Site: {2} | Status: {3}" -f `
           (Get-Date), $proto, $site, $statusMessage)
    }
} 
