import "pe"

rule ChrisProject_Malware_Behavior
{
    meta:
        description = "Detects potentially malware behaviors in Chris's executable"
        author = "Chris"
        classification = "benign sample for malware analysis training"
        behaviors = "networking, registry changes, filesystem changes, process execution, wallpaper modification"

    strings:
        // Network / downloader indicators
        $net1 = "InternetOpenUrlA" ascii
        $net2 = "InternetReadFile" ascii
        $url1 = "wallpapersafari.com" ascii

        // Registry modification indicators
        $reg_key = "Software\\Malware" ascii
        $reg_create = "[Registry] Created StringValue" ascii
        $reg_delete = "[Registry] Deleted" ascii

        // File system manipulation indicators
        $fs_dir1 = "C:\\ChrisProjectDir1" ascii
        $fs_dir2 = "C:\\ChrisProjectDir2" ascii
        $fs_msg = "[Files] Created directories and files." ascii

        // External process execution
        $proc_cmd = "C:\\Windows\\System32\\cmd.exe" ascii
        $proc_paint = "start mspaint.exe" ascii

        // Wallpaper modification
        $wall_dl = "[Wallpaper] Downloading..." ascii
        $wall_set = "[Wallpaper] Setting wallpaper." ascii

        // Suspicious message
        $msg_hacked = "YOU HAVE BEEN HACKED!!!!!!!!!" ascii

    condition:
        // ---- PE Characteristics (relaxed/failsafe) ----
        pe.machine == pe.MACHINE_AMD64 and
        pe.number_of_sections >= 6 and

        // Optional: check for any of the unusual MinGW sections (failsafe with OR)
        (
            for any i in (0..pe.number_of_sections - 1):
                (
                    pe.sections[i].name == ".rdata$zzz" or
                    pe.sections[i].name == ".ctors.65535" or
                    pe.sections[i].name == ".text.startup"
                )
        ) or
        1==1  // ensures it won't fail if section names differ slightly

        // ---- Behavioral Indicators ----
        and
        (
            2 of ($net*, $url*) or
            2 of ($reg*) or
            2 of ($fs*) or
            2 of ($proc*) or
            2 of ($wall*)
        )
        and $msg_hacked
}
