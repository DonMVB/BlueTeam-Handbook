$namespacesToCheck = @(
    "root\subscription",
    "root\cimv2",
    "root\default",
    "root\wmi",
    "root\security",
    "root\Microsoft\Windows\Defender"
)
$results = @()
foreach ($ns in $namespacesToCheck) {
    Write-Host "`nChecking namespace: $ns" -ForegroundColor Cyan

    # Checking for Event Filters
    try {
        $filters = Get-CimInstance -Namespace $ns -ClassName __EventFilter -ErrorAction Stop
        foreach ($f in $filters) {
            $results += [PSCustomObject]@{
                Namespace = $ns
                Type      = "EventFilter"
                Name      = $f.Name
                Query     = $f.Query
            }
        }
    } catch {}

    # Checking for Consumers (generic and subclasses)
    try {
        $consumers = Get-CimInstance -Namespace $ns -Query "SELECT * FROM __EventConsumer" -ErrorAction Stop
        foreach ($c in $consumers) {
            $results += [PSCustomObject]@{
                Namespace = $ns
                Type      = "EventConsumer"
                Name      = $c.Name
                Class     = $c.__Class
            }
        }
    } catch {}

    # Checking for Filter-to-Consumer Bindings
    try {
        $bindings = Get-CimInstance -Namespace $ns -ClassName __FilterToConsumerBinding -ErrorAction Stop
        foreach ($b in $bindings) {
            $results += [PSCustomObject]@{
                Namespace = $ns
                Type      = "Binding"
                Filter    = $b.Filter
                Consumer  = $b.Consumer
            }
        }
    } catch {}
}
