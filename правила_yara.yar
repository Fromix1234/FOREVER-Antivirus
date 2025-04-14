rule MalwareStrings {
    strings:
        $a = "malware"
        $b = "backdoor"
    condition:
        any of them
}