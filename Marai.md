```r
rule MaliciousDNS {
    strings:
        $s1 = "sdfsd.xyz"
        $s2 = "router.bittorrent.com"
        $s3 = "dht.transmissionbt.com"
        $s4 = "router.utorrent.com"
        $s5 = "bttracker.debian.org"
        $s6 = "c.wolfiot.xyz"
        $s7 = "gay.energy"
        $s8 = "cnc.alprazolam.rip"
        $s9 = "infectedchink.cat"
        $s10 = "cnsmaccas.duckdns.org"
        $s11 = "fuckmy.site"
    condition:
        any of them
}

rule C2Connection {
    strings:
        $a = "\x00\x00\x00\x01"    // Mirai Botnet: Register Bot with C&C
        $b = "\x00\x00"            // Mirai Botnet: Send Heartbeat from Bot to C&C
        $c = "\x00"
    condition:
        any of them
}

rule remote {
    strings:
        $a = "/bin/busybox BOTNET"
        $b = "GET /bins/mirai"
    condition:
        any of them
}

rule Defaultcredentials {
    strings:
        $a = "xc3511"
        $b = "vizxv"
        $c = "admin"
        $d = "888888"
        $e = "xmhdipc"
        $f = "default"
        $g = "123456"
        $h = "54321"
        $i = "support"
        $j = "password"
        $k = "root"
        $l = "user"
        $m = "12345"
        $n = "pass"
        $o = "admin1234"
        $p = "1111"
        $q = "smcadmin"
        $r = "666666"
        $s = "klv123"
        $t = "service"
        $u = "supervisor"
        $v = "ubnt"
        $w = "klv1234"
        $x = "Zte521"
        $y = "hi3518"
        $z = "jvbzd"
        $s1 = "anko"
        $s2 = "zlxx."
        $s3 = "7ujMko0vizxv"
        $s4 = "7ujMko0admin"
        $s5 = "ikwb"
        $s6 = "dreambox"
        $s7 = "realtek"
        $s8 = "00000000"
        $s9 = "meinsm"
        $s10 = "tech"
        $s11 = "user"
    condition:
        any of them
}

/*
The default credentials might give some false positives as the default credentials might overlap with some other valid packets can have some strings which might match these.
*/

rule HTTPFlood {
    strings:
        $a = /Mozilla\/\d\.\d+\s+\S+Windows\s+NT\s+10.0\;\s+WOW64\S+\s+AppleWebKit\/\d+\.\d+\s+\S+KHTML\,\s+like\s+Gecko\S+\s+Chrome\/\d+\.\d\.\d+\.\d+\s+Safari\/\d+\.\d+/
        $b = /Mozilla\/\d\.\d+\s+\S+Macintosh\;\s+Intel\s+Mac\s+OS\s+X\s+\d+.\d+.\d+\S+\s+AppleWebKit\/\d+\.\d.\d+\s+\S+KHTML\,\s+like\s+Gecko\S+\s+Version\/\d+.\d+.\d+\s+Safari\/\d+.\d+.\d+/
    condition:
        any of them
}
```