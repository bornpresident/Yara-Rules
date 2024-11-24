/*
BlackCat / ALPHV ransomware
*/

rule BlackCat
{
    meta:
        author = "Andrey Zhdanov"
        family = "ransomware.blackcat"
        description = "BlackCat ransomware Windows/Linux payload"
        severity = 10
        score = 100

    strings:
        $n0 = { ( B8 01 00 00 00 31 C9 | 31 C9 B8 01 00 00 00 )
                [0-2] 89 DE 0F A2 87 F3 89 CE [0-8]
                ( B8 07 00 00 00 31 C9 | 31 C9 B8 07 00 00 00 )
                [0-2] 81 E6 00 00 00 02 [0-2] 0F A2 [0-14] C1 E8 19 85 F6 }
        $n1 = { ( B8 01 00 00 00 31 C9 | 31 C9 B8 01 00 00 00 )
                ( 89 | 48 89 ) DE 0F A2 ( 87 | 48 87 ) F3 89 C?
                ( B8 07 00 00 00 31 C9 | 31 C9 B8 07 00 00 00 )
                [0-4] 0F A2 [0-8] C1 E? 19 ( 24 01 | 40 80 E6 01 ) }
        $c0 = { 66 0F 72 ( F? 0C 66 0F 72 D? 14 | D? 14 66 0F 72 F? 0C )
                66 0F EB ?? }
        $c1 = { 66 0F 72 ( F? 07 66 0F 72 D? 19 | D? 19 66 0F 72 F? 07 )
                66 0F EB ?? }

        $x0 = { 8D ( 4D ?? | 4C 24 ?? | 8D ?? FF FF FF) BA [4]
                68 1A 0C 06 00 E8 }
        $x1 = { 8D ( 4D | 4C 24 | 8C 24 [2] ?? ) ?? BA [4] 6A 7B E8 }
        $y0 = { 68 1A 0C 06 00 68 [4] 50 E8 }
        $y1 = { 6A 7B 68 [4] 50 E8 }
        $z0  = { 68 C0 1F 00 00 68 [4] 5? E8 }

        $a01 = "src/bin/encrypt_app/app.rs" ascii
        $a02 = "encrypt_app::windows" ascii
        $a03 = "src/bin/encrypt_app/windows.rs" ascii
        $a04 = "encrypt_app::linux" ascii
        $a05 = "src/bin/encrypt_app/linux.rs" ascii
        $a06 = "library/encrypt-lib/src/app.rs" ascii
        $a07 = "encrypt_lib::windows" ascii
        $a08 = "library/encrypt-lib/src/windows.rs" ascii
        $a09 = "library/encrypt-lib/src/linux.rs" ascii
        $a10 = "encrypt_lib::linux" ascii
        $a11 = "psexec_args=" ascii
        $a12 = "psexec_args::args=" ascii
        $a13 = "locker::core::" ascii
        $a14 = "set_desktop_image::" ascii
        $a15 = "::pipeline::file_worker_pool" ascii
        $a16 = "::pipeline::chunk_workers_supervisor" ascii
        $a17 = "::os::windows::privilege_escalation" ascii
        $a18 = "::os::windows::samba" ascii
        $a19 = "::os::windows::system_info" ascii
        $a20 = "::os::windows::netbios" ascii
        $a21 = "hidden_partitions::mount_all::mounting=" ascii
        $a22 = "uac_bypass::shell_exec=" ascii
        $a23 = "-u-p-s-d-f-cpropagate::attempt=" ascii
        $a24 = "enum_dependent_services" ascii
        $a25 = "masquerade_peb" ascii
        $a26 = "AdvancedSmartPattern" ascii

        $b01 = "note_file_name" ascii
        $b02 = "note_full_text" ascii
        $b03 = "note_short_text" ascii
        $b04 = "default_file_cipher" ascii
        $b05 = "default_file_mode" ascii
        $b06 = "note_full_text" ascii
        $b07 = "exclude_file_path_wildcard" ascii
        $b08 = "exclude_file_extensions" ascii
        $b09 = "enable_network_discovery" ascii
        $b10 = "enable_self_propagation" ascii
        $b11 = "enable_set_wallpaper" ascii
        $b12 = "enable_esxi_vm_kill" ascii
        $b13 = "enable_esxi_vm_snapshot_kill" ascii
        $b14 = "strict_include_paths" ascii
        $b15 = "esxi_vm_kill_exclude" ascii
        $b16 = "drop-drag-and-drop-target" ascii
        $b17 = "no-vm-kill" ascii
        $b18 = "no-vm-snapshot-kill" ascii
        $b19 = "no-prop-servers" ascii

    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            ((1 of ($n*)) and (2 of ($c*))) or
            ($z0 and ((all of ($x*)) or (all of ($y*)))) or
            (7 of ($a*)) or
            (5 of ($b*))
        )
}


rule BlackCat3
{
    meta:
        author = "rivitna"
        family = "ransomware.blackcat3"
        description = "BlackCat v3 ransomware Windows/Linux payload"
        severity = 10
        score = 100

    strings:
        $x0  = { 6A 01 68 80 3F 00 00 E8 [4] [4-32] 68 80 3F 00 00 68 [4]
                 5? E8 }
        $y0 = { 8D ( 4D ?? | 4C 24 ?? | 8D ?? FF FF FF) BA [4]
                68 1A 0C 06 00 E8 }
        $y1 = { 8D ( 4D | 4C 24 | 8C 24 [2] ?? ) ?? BA [4] 6A 7B E8 }
        $y2 = { 68 1A 0C 06 00 68 [4] 50 E8 }
        $y3 = { 6A 7B 68 [4] 50 E8 }

        $m0  = { 0F B6 02 0F B6 F3 42 66 0F A4 D8 08 66 33 84 36 [4] 49
                 89 C3 75 E7 }
        $m1  = { 0F B6 C1 C1 E9 08 0F B7 84 00 [4] 31 C1 C1 E8 08 0F B6 C9
                 66 33 84 09 }
        $m2  = { 0F B6 44 3E 01 66 0F A4 C8 08 48 83 C7 02 66 43 33 04 51
                 48 39 F? }
        $m3  = { 0F B7 04 4E 31 C2 0F B6 CA C1 E8 08 66 33 04 4E }
        $m4  = { 8A ?C 0? 08 [0-8] 80 F? FF 0F 84 [2] 00 00 [8-40]
                 ( 0F B6 ?? [0-8] F7 64 ?? FC | F7 64 ?? FC [0-8] 0F B6 ?? )
                 [0-8] 01 C? }
        $m5  = { 8A 54 03 10 80 FA FF 0F 84 [20-68] 8B 7C B0 FC 49 0F AF FF
                 44 0F B6 F2 49 01 FE }

        $n0 = { 6A 00 6A 07 5? E8 [4] 83 C4 0? B8 00 00 00 02
                23 84 24 ?? ?? 00 00 89 C1 C1 E9 19 85 C0 }
        $n1 = { BE 07 00 00 00 31 D2 FF 15 [4] B8 00 00 00 02
                23 84 24 ?? ?? 00 00 89 C1 C1 E9 19 [0-12] 85 C0 }

        $e0 = { 66 0F 7F 89 80 00 00 00 66 0F 38 DB 92 90 00 00 00
                0F 28 8A A0 00 00 00 66 0F 7F 91 90 00 00 00
                0F 29 89 A0 00 00 00 5D }
        $e1 = { 66 0F 70 84 24 ?? ?? 00 00 FF 66 0F 6F 5C 24 ?? 66 0F 6F CB
                66 0F 73 F9 04 66 0F EF CB 66 0F 6F D3 66 0F 73 FA 08
                66 0F 73 FB 0C 66 0F EF DA 66 0F EF D9 66 0F EF D8 }
        $e2 = { 66 0F 6F 5C 24 ?? 66 0F 70 84 24 ?? ?? 00 00 FF [0-16]
                66 0F 6F CB 66 0F 6F D3 66 0F 6F E3 66 0F 73 F9 04
                66 0F 73 FA 08 66 0F 73 FC 0C 66 0F EF D1 66 0F EF E2
                66 0F EF E0 66 0F EF E3 }

        $c0 = { 66 0F 6F C8 66 0F 72 F0 08 [0-4] 66 0F 72 D1 18 [0-24]
                66 0F EB C1 }
        $c1 = { 66 0F 72
                ( F? 07 [0-12] 66 0F 72 D? 19 |
                  D? 19 [0-12] 66 0F 72 F? 07 )
                [0-24] 66 0F EB ?? }

    condition:
        (((uint16(0) == 0x5A4D) and (uint32(uint32(0x3C)) == 0x00004550)) or
         (uint32(0) == 0x464C457F)) and
        (
            ($x0 and (1 of ($y*))) or
            (2 of ($m*)) or
            ((1 of ($n*)) and (1 of ($e*)) and (1 of ($c*)))
        )
}
