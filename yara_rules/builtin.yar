/*
 * 組み込みYARAルール（自作・手書き）。
 * より網羅的な検知が必要な場合は yara_rule_import.py で
 * コミュニティ公開ルール（Yara-Rules/rules 等）を取り込んでください。
 * パケット解析（メール添付・抽出ファイル）に対して適用されます。
 */

rule Mimikatz_Indicators
{
    meta:
        description = "Mimikatz（認証情報窃取ツール）の既知コマンド/モジュール名を検出"
        severity = "critical"
        reference = "https://github.com/gentilkiwi/mimikatz"
    strings:
        $a = "sekurlsa::logonpasswords" nocase
        $b = "kerberos::golden" nocase
        $c = "lsadump::sam" nocase
        $d = "privilege::debug" nocase
    condition:
        any of them
}

rule PowerShell_Obfuscation
{
    meta:
        description = "難読化されたPowerShellコマンド（Base64エンコード実行）の兆候"
        severity = "high"
    strings:
        $enc1 = "-EncodedCommand" nocase
        $enc2 = "-enc " nocase
        $enc3 = "-ec " nocase
        $b64  = "FromBase64String" nocase
        $iex  = "IEX" nocase
        $hidden = "-WindowStyle Hidden" nocase
    condition:
        $enc1 or $enc2 or $enc3 or ($hidden and $b64) or ($iex and $b64)
}

rule Webshell_PHP_Eval_Chain
{
    meta:
        description = "PHP Webシェルに典型的なbase64_decode+eval連鎖、または$_POST直接実行"
        severity = "critical"
    strings:
        $a = "eval(base64_decode(" nocase
        $b = "eval($_POST[" nocase
        $c = "assert($_POST[" nocase
        $d = "system($_GET[" nocase
        $e = "passthru($_REQUEST[" nocase
    condition:
        any of them
}

rule CobaltStrike_Default_NamedPipe
{
    meta:
        description = "Cobalt Strikeデフォルト設定のSMB Beacon名前付きパイプパターン"
        severity = "critical"
        note = "設定変更（malleable C2プロファイル）で容易に回避されるため、検知なし=安全の確証にはならない"
    strings:
        $a = "\\\\.\\pipe\\MSSE-" nocase
        $b = "\\\\.\\pipe\\status_" nocase
    condition:
        any of them
}

rule UPX_Packed_Binary
{
    meta:
        description = "UPXでパッキングされた実行ファイル（マルウェアの難読化によく使われる圧縮形式）"
        severity = "medium"
    strings:
        $magic = "UPX!"
        $sec0 = "UPX0"
        $sec1 = "UPX1"
    condition:
        $magic and ($sec0 or $sec1)
}

rule Generic_Reverse_Shell_Snippet
{
    meta:
        description = "古典的なbash/ncリバースシェルのワンライナー断片"
        severity = "critical"
    strings:
        $a = "/bin/sh -i" nocase
        $b = "0>&1"
        $c = "bash -i >& /dev/tcp/" nocase
        $d = "nc -e /bin/sh" nocase
    condition:
        $c or $d or ($a and $b)
}

rule EICAR_Test_String
{
    meta:
        description = "AV動作確認用のEICARテスト文字列"
        severity = "medium"
        reference = "https://www.eicar.org/download-anti-malware-testfile/"
    strings:
        $eicar = "X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    condition:
        $eicar
}
