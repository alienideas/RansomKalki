# VectorStryke ResponsePolicy — OOP decision engine
# Automatic = fully automatic, no approvals
# Manual    = approvals required; timeout never auto-acts

class VSResponsePolicy {
    [hashtable]$Config

    VSResponsePolicy([hashtable]$Config) {
        $this.Config = $Config
    }

    [void] Reload([hashtable]$Config) { $this.Config = $Config }

    [string] Mode() {
        $m = [string]$this.Config.ResponseMode
        if (-not $m) { return "Automatic" }
        return $m
    }

    [bool] IsAutomatic() { return $this.Mode() -eq "Automatic" }
    [bool] IsManual() { return -not $this.IsAutomatic() }

    [bool] ShouldActImmediately([hashtable]$Finding) {
        if (-not $this.Config.AgentEnabled) { return $false }
        $score = 0
        if ($Finding.ContainsKey("score")) { $score = [int]$Finding.score }
        elseif ($Finding.ContainsKey("Score")) { $score = [int]$Finding.Score }
        $state = [string]$this.Config.FirstRunState
        if ($this.IsAutomatic()) {
            if ($state -ne "Steady") {
                $impact = $false
                if ($Finding.ContainsKey("impact_class")) { $impact = [bool]$Finding.impact_class }
                if (-not $impact -and $score -lt 90) { return $false }
            }
            return $score -ge 60
        }
        return $false
    }

    [bool] RequiresHumanApproval([hashtable]$Finding) {
        return $this.IsManual()
    }

    [bool] AllowTimeoutAutoAction() {
        return $false
    }
}
