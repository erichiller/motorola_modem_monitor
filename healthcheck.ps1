
try {
    if ( (Get-ChildItem "C:\healthtouch" | New-TimeSpan).TotalSeconds -gt 240 ) {
        return 1;
    } else { 
        return 0;
    }
} catch { 
    return 1;
}