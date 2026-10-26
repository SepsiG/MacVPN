# The WinVPN 2c RAS spike (docs/superpowers/plans/2026-10-25-winvpn-2c-native-vpns.md, Task 2; findings in
# docs/superpowers/spikes/2026-10-25-winvpn-ras.md). Kept for re-runs on a new Windows build; WinVPN itself never runs
# PowerShell. Runs as a standard user; needs no administrator rights and installs nothing.
#
#   powershell -NoProfile -ExecutionPolicy Bypass -File scripts\ras-spike.ps1 capture -Out DIR
#       Microsoft's reference entries: Add-VpnConnection in the current user's default phonebook (entries
#       "WinVPN-spike-<n>", removed again), each entry's phonebook section into DIR\fixtures\<name>.pbk and its
#       RASENTRYW fields into DIR\fixtures\ras_entry_fields.txt. Needs the desktop session: the VpnClient cmdlets'
#       CIM provider refuses an SSH (network) logon ("Access denied").
#   powershell ... -File scripts\ras-spike.ps1 probe -Out DIR [-Fixtures DIR]
#       The private phonebook checks (%LOCALAPPDATA%\WinVPN-spike\ras\spike.pbk): write/read entries, dial
#       192.0.2.1 (TEST-NET-1, never answers), hang up, enumerate, the notification, the PSK store, the IPsec policy
#       keys, the device rule. Everything it creates is deleted at the end. Works over SSH and at the desktop.
#   powershell ... -File scripts\ras-spike.ps1 all -Out DIR       capture, then probe with DIR\fixtures
#
# Only dummy values are used: the PSK 'spike-psk-not-secret', the user 'spike-user', the password
# 'spike-password-not-secret', servers vpn.example.com / 192.0.2.1. Output: DIR\spike.log (and the fixtures).
param(
  [Parameter(Mandatory = $true, Position = 0)][ValidateSet('capture', 'probe', 'all')][string]$Mode,
  [Parameter(Mandatory = $true)][string]$Out,
  [string]$Fixtures = '',
  [switch]$SkipDial
)
$ErrorActionPreference = 'Stop'
New-Item -ItemType Directory -Force -Path $Out | Out-Null
$LogFile = Join-Path $Out 'spike.log'
function Log([string]$Text) { Add-Content -Encoding UTF8 -Path $LogFile -Value $Text; $Text | Out-Host }

$DummyPsk = 'spike-psk-not-secret'
$DummyUser = 'spike-user'
$DummyPassword = 'spike-password-not-secret'
$Unreachable = '192.0.2.1'

Add-Type -TypeDefinition @'
using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Reflection;
using System.Runtime.InteropServices;
using System.Text;
using System.Threading;

public static class Ras {
  // ras.h (Windows 8+ layouts; field order as windows-sys 0.61.2 Win32::NetworkManagement::Rras).
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct RASENTRYW {
    public int dwSize; public uint dwfOptions; public int dwCountryID; public int dwCountryCode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 11)] public string szAreaCode;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szLocalPhoneNumber;
    public int dwAlternateOffset;
    public uint ipaddr; public uint ipaddrDns; public uint ipaddrDnsAlt; public uint ipaddrWins; public uint ipaddrWinsAlt;
    public int dwFrameSize; public uint dwfNetProtocols; public uint dwFramingProtocol;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szScript;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szAutodialDll;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szAutodialFunc;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string szDeviceType;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szDeviceName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 33)] public string szX25PadType;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 201)] public string szX25Address;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 201)] public string szX25Facilities;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 201)] public string szX25UserData;
    public int dwChannels; public int dwReserved1; public int dwReserved2;
    public int dwSubEntries; public uint dwDialMode; public int dwDialExtraPercent; public int dwDialExtraSampleSeconds;
    public int dwHangUpExtraPercent; public int dwHangUpExtraSampleSeconds; public int dwIdleDisconnectSeconds;
    public uint dwType; public uint dwEncryptionType; public uint dwCustomAuthKey;
    public Guid guidId;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szCustomDialDll;
    public uint dwVpnStrategy; public uint dwfOptions2; public uint dwfOptions3;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 256)] public string szDnsSuffix;
    public int dwTcpWindowSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szPrerequisitePbk;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szPrerequisiteEntry;
    public int dwRedialCount; public int dwRedialPause;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ipv6addrDns;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ipv6addrDnsAlt;
    public uint dwIPv4InterfaceMetric; public uint dwIPv6InterfaceMetric;
    [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] ipv6addr;
    public int dwIPv6PrefixLength; public int dwNetworkOutageTime;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szIDi;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szIDr;
    public int fIsImsConfig; public int IdiType; public int IdrType; public int fDisableIKEv2Fragmentation;
  }

  // ras.h is #include <pshpack4.h>: on 64-bit the pointer-sized fields are 4-aligned (windows-sys: packed(4)).
  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
  public struct RASDIALPARAMSW {
    public int dwSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szEntryName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szPhoneNumber;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szCallbackNumber;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szUserName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szPassword;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] public string szDomain;
    public int dwSubEntry; public UIntPtr dwCallbackId; public int dwIfIndex; public IntPtr szEncPassword;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode, Pack = 4)]
  public struct RASCONNW {
    public int dwSize; public IntPtr hrasconn;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szEntryName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string szDeviceType;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szDeviceName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 260)] public string szPhonebook;
    public int dwSubEntry; public Guid guidEntry; public int dwFlags; public uint luidLow; public int luidHigh;
    public Guid guidCorrelationId;
  }

  [StructLayout(LayoutKind.Sequential)]
  public struct RASTUNNELENDPOINT {
    public int dwType; [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)] public byte[] addr;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct RASCONNSTATUSW {
    public int dwSize; public int rasconnstate; public int dwError;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string szDeviceType;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szDeviceName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szPhoneNumber;
    public RASTUNNELENDPOINT localEndPoint; public RASTUNNELENDPOINT remoteEndPoint; public int rasconnsubstate;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct RASENTRYNAMEW {
    public int dwSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szEntryName;
    public int dwFlags;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 261)] public string szPhonebookPath;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct RASCREDENTIALSW {
    public int dwSize; public uint dwMask;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szUserName;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 257)] public string szPassword;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 16)] public string szDomain;
  }

  [StructLayout(LayoutKind.Sequential, CharSet = CharSet.Unicode)]
  public struct RASDEVINFOW {
    public int dwSize;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 17)] public string szDeviceType;
    [MarshalAs(UnmanagedType.ByValTStr, SizeConst = 129)] public string szDeviceName;
  }

  public delegate void RasDialFunc1(IntPtr hrasconn, uint unMsg, int rascs, int dwError, int dwExtendedError);

  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasSetEntryPropertiesW(string pbk, string entry, ref RASENTRYW e, int cb, IntPtr dev, int cbDev);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasGetEntryPropertiesW(string pbk, string entry, ref RASENTRYW e, ref int cb, IntPtr dev, IntPtr cbDev);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasDeleteEntryW(string pbk, string entry);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasValidateEntryNameW(string pbk, string entry);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasDialW(IntPtr ext, string pbk, ref RASDIALPARAMSW p, uint notifierType, RasDialFunc1 notifier, out IntPtr h);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasHangUpW(IntPtr h);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasGetConnectStatusW(IntPtr h, ref RASCONNSTATUSW s);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasEnumConnectionsW(IntPtr buf, ref int cb, out int count);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasEnumEntriesW(IntPtr reserved, string pbk, IntPtr buf, ref int cb, out int count);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasEnumDevicesW(IntPtr buf, ref int cb, out int count);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasSetCredentialsW(string pbk, string entry, ref RASCREDENTIALSW c, int fClear);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasGetCredentialsW(string pbk, string entry, ref RASCREDENTIALSW c);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasConnectionNotificationW(IntPtr h, IntPtr ev, uint flags);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasSetCustomAuthDataW(string pbk, string entry, byte[] data, int cb);
  [DllImport("rasapi32.dll", CharSet = CharSet.Unicode)] public static extern int RasGetErrorStringW(int code, StringBuilder buf, int cch);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern int GetPrivateProfileStringW(string sec, string key, string def, StringBuilder buf, int cch, string file);
  [DllImport("kernel32.dll", CharSet = CharSet.Unicode)] public static extern bool WritePrivateProfileStringW(string sec, string key, string val, string file);

  // ras.h values (windows-sys 0.61.2).
  public const uint RASEO_RemoteDefaultGateway = 0x10, RASEO_RequireEncryptedPw = 0x400, RASEO_RequireMsEncryptedPw = 0x800,
    RASEO_RequireDataEncryption = 0x1000, RASEO_RequireEAP = 0x20000, RASEO_RequireMsCHAP2 = 0x20000000,
    RASEO_ModemLights = 0x100, RASEO_SecureLocalFiles = 0x10000, RASEO_PreviewUserPw = 0x1000000,
    RASEO_ShowDialingProgress = 0x4000000;
  public const uint RASEO2_UsePreSharedKey = 0x10, RASEO2_DontNegotiateMultilink = 0x4, RASEO2_ReconnectIfDropped = 0x100,
    RASEO2_IPv4ExplicitMetric = 0x10000, RASEO2_IPv6ExplicitMetric = 0x20000, RASEO2_IPv6RemoteDefaultGateway = 0x2000,
    RASEO2_RequireMachineCertificates = 0x400000, RASEO2_UsePreSharedKeyForIkev2Initiator = 0x800000,
    RASEO2_CacheCredentials = 0x2000000, RASEO2_PlumbIKEv2TSAsRoutes = 0x80000000;
  public const uint VS_L2tpOnly = 3, VS_SstpOnly = 5, VS_Ikev2Only = 7, ET_Require = 1, RASET_Vpn = 2, RASFP_Ppp = 1,
    RASNP_Ip = 4, RASNP_Ipv6 = 8;
  public const uint RASCM_UserName = 1, RASCM_Password = 2, RASCM_PreSharedKey = 0x10;

  public static RASENTRYW NewEntry() {
    RASENTRYW e = new RASENTRYW();
    e.dwSize = Marshal.SizeOf(typeof(RASENTRYW));
    e.ipv6addrDns = new byte[16]; e.ipv6addrDnsAlt = new byte[16]; e.ipv6addr = new byte[16];
    return e;
  }

  // The plan's first guess at each kind's entry (Resolved points, "Per-kind mapping"); the spike compares the result
  // with Microsoft's reference entries.
  // Microsoft's reference entries (capture) without the rasphone UI bits (RASEO_PreviewUserPw, PreviewDomain,
  // ShowDialingProgress, ModemLights): what Task 3/5 should write. encRequire: SSTP/IKEv2 with ET_Require +
  // RASEO_RequireDataEncryption instead of Add-VpnConnection's default ET_Optional.
  public static RASENTRYW PlanEntry(string kind, string server, bool fullTunnel, string device) { return Plan(kind, server, fullTunnel, device, false); }
  public static RASENTRYW Plan(string kind, string server, bool fullTunnel, string device, bool encRequire) {
    RASENTRYW e = NewEntry();
    e.dwType = RASET_Vpn; e.dwFramingProtocol = RASFP_Ppp; e.dwfNetProtocols = RASNP_Ip | RASNP_Ipv6;
    e.szDeviceType = "vpn"; e.szDeviceName = device; e.szLocalPhoneNumber = server;
    e.dwDialMode = 0; e.dwRedialCount = 3; e.dwRedialPause = 60;
    e.dwfOptions2 = RASEO2_DontNegotiateMultilink | RASEO2_ReconnectIfDropped;
    if (fullTunnel) { e.dwfOptions |= RASEO_RemoteDefaultGateway; e.dwfOptions2 |= RASEO2_IPv6RemoteDefaultGateway; }
    uint ppp = RASEO_RequireMsCHAP2 | RASEO_RequireMsEncryptedPw | RASEO_RequireEncryptedPw;
    switch (kind) {
      case "l2tp": e.dwVpnStrategy = VS_L2tpOnly; e.dwfOptions |= ppp | RASEO_RequireDataEncryption; e.dwEncryptionType = ET_Require; e.dwfOptions2 |= RASEO2_UsePreSharedKey; return e;
      case "sstp": e.dwVpnStrategy = VS_SstpOnly; e.dwfOptions |= ppp; break;
      // IKEv2 refuses (87) RASEO_RequireMsEncryptedPw / RequireMsCHAP2 and an entry with neither RASEO_RequireEAP nor
      // RASEO2_RequireMachineCertificates (check 1a); the PSK initiator flag is accepted only next to one of them.
      case "ikev2eap": e.dwVpnStrategy = VS_Ikev2Only; e.dwfOptions |= RASEO_RequireEAP; e.dwCustomAuthKey = 26; e.dwNetworkOutageTime = 1800; break;
      case "ikev2psk": e.dwVpnStrategy = VS_Ikev2Only; e.dwfOptions |= RASEO_RequireEAP; e.dwCustomAuthKey = 26; e.dwNetworkOutageTime = 1800; e.dwfOptions2 |= RASEO2_UsePreSharedKeyForIkev2Initiator; break;
      case "ikev2pskcert": e.dwVpnStrategy = VS_Ikev2Only; e.dwNetworkOutageTime = 1800; e.dwfOptions2 |= RASEO2_RequireMachineCertificates | RASEO2_UsePreSharedKeyForIkev2Initiator; break;
      case "ikev2cert": e.dwVpnStrategy = VS_Ikev2Only; e.dwNetworkOutageTime = 1800; e.dwfOptions2 |= RASEO2_RequireMachineCertificates; break;
      default: throw new ArgumentException(kind);
    }
    if (encRequire) { e.dwEncryptionType = ET_Require; e.dwfOptions |= RASEO_RequireDataEncryption; } else e.dwEncryptionType = 3; // ET_Optional
    return e;
  }

  public static string Describe(RASENTRYW e) {
    StringBuilder sb = new StringBuilder();
    foreach (FieldInfo f in typeof(RASENTRYW).GetFields()) {
      object v = f.GetValue(e);
      if (v == null) continue;
      string s;
      if (v is byte[]) { byte[] b = (byte[])v; bool zero = true; foreach (byte x in b) if (x != 0) zero = false; if (zero) continue; s = BitConverter.ToString(b); }
      else if (v is string) { if (((string)v).Length == 0) continue; s = "\"" + v + "\""; }
      else if (v is uint) { if ((uint)v == 0) continue; s = "0x" + ((uint)v).ToString("X8"); }
      else if (v is int) { if ((int)v == 0) continue; s = v.ToString(); }
      else s = v.ToString();
      sb.Append("  ").Append(f.Name).Append(" = ").Append(s).Append("\n");
    }
    return sb.ToString();
  }

  public static string ErrText(int code) {
    StringBuilder sb = new StringBuilder(512);
    if (RasGetErrorStringW(code, sb, sb.Capacity) == 0) return sb.ToString();
    try { return new System.ComponentModel.Win32Exception(code).Message; } catch { return "?"; }
  }

  public static int SetEntry(string pbk, string name, RASENTRYW e) {
    e.dwSize = Marshal.SizeOf(typeof(RASENTRYW));
    return RasSetEntryPropertiesW(pbk, name, ref e, e.dwSize, IntPtr.Zero, 0);
  }

  public static int GetEntry(string pbk, string name, out RASENTRYW e) {
    e = NewEntry();
    int cb = e.dwSize;
    return RasGetEntryPropertiesW(pbk, name, ref e, ref cb, IntPtr.Zero, IntPtr.Zero);
  }

  public static List<string> Devices() {
    List<string> r = new List<string>();
    int sz = Marshal.SizeOf(typeof(RASDEVINFOW));
    int cb = sz * 64; int n;
    IntPtr buf = Marshal.AllocHGlobal(cb);
    try {
      Marshal.WriteInt32(buf, sz);
      int rc = RasEnumDevicesW(buf, ref cb, out n);
      if (rc != 0) { r.Add("RasEnumDevicesW rc=" + rc); return r; }
      for (int i = 0; i < n; i++) {
        RASDEVINFOW d = (RASDEVINFOW)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + i * sz), typeof(RASDEVINFOW));
        r.Add(d.szDeviceType + " | " + d.szDeviceName);
      }
    } finally { Marshal.FreeHGlobal(buf); }
    return r;
  }

  public static int ConnSize = 0;
  public static List<RASCONNW> Connections(out int rc) {
    List<RASCONNW> r = new List<RASCONNW>();
    int sz = Marshal.SizeOf(typeof(RASCONNW));
    int cb = sz * 32; int n;
    IntPtr buf = Marshal.AllocHGlobal(cb);
    try {
      rc = 632; n = 0;
      // As RasDialW: the first dwSize that is not ERROR_INVALID_SIZE (632) is used (and recorded in ConnSize).
      foreach (int size in new int[] { sz, 1360 }) {
        cb = size * 32;
        for (int i = 0; i < 32; i++) Marshal.WriteInt32(new IntPtr(buf.ToInt64() + i * size), size);
        rc = RasEnumConnectionsW(buf, ref cb, out n);
        if (rc != 632) { ConnSize = size; sz = size; break; }
      }
      if (rc != 0) return r;
      for (int i = 0; i < n; i++) r.Add((RASCONNW)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + i * sz), typeof(RASCONNW)));
    } finally { Marshal.FreeHGlobal(buf); }
    return r;
  }

  public static List<string> Entries(string pbk, out int rc) {
    List<string> r = new List<string>();
    int sz = Marshal.SizeOf(typeof(RASENTRYNAMEW));
    int cb = sz * 256; int n;
    IntPtr buf = Marshal.AllocHGlobal(cb);
    try {
      Marshal.WriteInt32(buf, sz);
      rc = RasEnumEntriesW(IntPtr.Zero, pbk, buf, ref cb, out n);
      if (rc != 0) return r;
      for (int i = 0; i < n; i++) {
        RASENTRYNAMEW x = (RASENTRYNAMEW)Marshal.PtrToStructure(new IntPtr(buf.ToInt64() + i * sz), typeof(RASENTRYNAMEW));
        r.Add(x.szEntryName + " | flags=" + x.dwFlags + " | " + x.szPhonebookPath);
      }
    } finally { Marshal.FreeHGlobal(buf); }
    return r;
  }

  public static int SetPsk(string pbk, string name, string psk, bool clear) {
    RASCREDENTIALSW c = new RASCREDENTIALSW();
    c.dwSize = Marshal.SizeOf(typeof(RASCREDENTIALSW)); c.dwMask = RASCM_PreSharedKey; c.szPassword = psk;
    return RasSetCredentialsW(pbk, name, ref c, clear ? 1 : 0);
  }

  public static string GetCreds(string pbk, string name, uint mask) {
    RASCREDENTIALSW c = new RASCREDENTIALSW();
    c.dwSize = Marshal.SizeOf(typeof(RASCREDENTIALSW)); c.dwMask = mask;
    int rc = RasGetCredentialsW(pbk, name, ref c);
    // The password field is never printed: only whether it is empty.
    return "rc=" + rc + " dwMask=0x" + c.dwMask.ToString("X") + " password " + (string.IsNullOrEmpty(c.szPassword) ? "empty" : "non-empty (" + c.szPassword.Length + " chars)");
  }

  // ---- dialling ----
  static readonly Stopwatch Clock = Stopwatch.StartNew();
  public static readonly ConcurrentQueue<string> Events = new ConcurrentQueue<string>();
  static RasDialFunc1 keepAlive;
  static int lastState = -1, lastError = 0;
  static IntPtr cbHandle = IntPtr.Zero;
  static void Ev(string s) { Events.Enqueue(Clock.ElapsedMilliseconds.ToString("D7") + " ms  " + s); }
  public static string Drain() { StringBuilder sb = new StringBuilder(); string s; while (Events.TryDequeue(out s)) sb.Append("    ").Append(s).Append("\n"); return sb.ToString(); }

  static AutoResetEvent notifyEvent; static Thread notifyThread; static volatile bool notifyStop;
  public static int StartNotifications() {
    notifyEvent = new AutoResetEvent(false);
    int rc = RasConnectionNotificationW(new IntPtr(-1), notifyEvent.SafeWaitHandle.DangerousGetHandle(), 1 | 2);
    if (rc != 0) return rc;
    notifyThread = new Thread(delegate () { while (!notifyStop) { if (notifyEvent.WaitOne(200)) Ev("RASCN event (RasConnectionNotificationW, INVALID_HANDLE_VALUE, Connection|Disconnection)"); } });
    notifyThread.IsBackground = true; notifyThread.Start();
    return 0;
  }
  public static void StopNotifications() { notifyStop = true; if (notifyThread != null) notifyThread.Join(1000); }

  static string Netstat(string port) {
    try {
      ProcessStartInfo psi = new ProcessStartInfo("netstat.exe", "-n -p tcp");
      psi.RedirectStandardOutput = true; psi.UseShellExecute = false; psi.CreateNoWindow = true;
      Process p = Process.Start(psi); string o = p.StandardOutput.ReadToEnd(); p.WaitForExit();
      StringBuilder sb = new StringBuilder();
      foreach (string line in o.Split('\n')) if (line.Contains("192.0.2.1:")) sb.Append(line.Trim()).Append("; ");
      return sb.Length == 0 ? "(no TCP to 192.0.2.1)" : sb.ToString();
    } catch (Exception ex) { return "netstat failed: " + ex.Message; }
  }

  // Dials asynchronously, records the callback states, RasEnumConnectionsW once after ~1 s (phonebook path form),
  // optionally the TCP sockets towards 192.0.2.1, hangs up after hangupAfterMs (or when the dial fails, or at
  // timeoutMs), then measures how long RasGetConnectStatusW takes to answer ERROR_INVALID_HANDLE.
  public static string Dial(string pbk, string name, string user, string pass, int timeoutMs, int hangupAfterMs, bool netstat) {
    StringBuilder r = new StringBuilder();
    lastState = -1; lastError = 0;
    cbHandle = IntPtr.Zero;
    keepAlive = delegate (IntPtr h, uint msg, int st, int err, int ext) {
      lastState = st; if (err != 0) lastError = err; cbHandle = h;
      Ev("callback state=" + st + " error=" + err + " (0x" + err.ToString("X8") + ") ext=" + ext + " hrasconn=0x" + h.ToInt64().ToString("X"));
    };
    RASDIALPARAMSW p = new RASDIALPARAMSW();
    p.dwSize = Marshal.SizeOf(typeof(RASDIALPARAMSW)); p.szEntryName = name; p.szUserName = user; p.szPassword = pass;
    IntPtr hc = IntPtr.Zero;
    long t0 = Clock.ElapsedMilliseconds;
    int rc = 632;
    // RasDialW accepts only some dwSize values: the first one that is not ERROR_INVALID_SIZE (632) is recorded.
    foreach (int size in new int[] { Marshal.SizeOf(typeof(RASDIALPARAMSW)), 2128 }) {
      p.dwSize = size;
      t0 = Clock.ElapsedMilliseconds;
      rc = RasDialW(IntPtr.Zero, pbk, ref p, 1, keepAlive, out hc);
      if (rc != 632) break;
    }
    p.szPassword = null;
    r.Append("  RasDialW rc=" + rc + " handle=0x" + hc.ToInt64().ToString("X") + " (RASDIALPARAMSW dwSize " + p.dwSize + ", marshalled size " + Marshal.SizeOf(typeof(RASDIALPARAMSW)) + ")\n");
    if (rc != 0) { r.Append("  error text: " + ErrText(rc) + "\n"); if (hc != IntPtr.Zero) RasHangUpW(hc); return r.ToString(); }
    bool enumerated = false; string ports = "";
    while (true) {
      long el = Clock.ElapsedMilliseconds - t0;
      if (!enumerated && el > 1000) {
        enumerated = true; int erc;
        foreach (RASCONNW c in Connections(out erc)) r.Append("  RasEnumConnectionsW during dial (dwSize " + ConnSize + "): entry=\"" + c.szEntryName + "\" phonebook=\"" + c.szPhonebook + "\" device=\"" + c.szDeviceName + "\" flags=0x" + c.dwFlags.ToString("X") + " hrasconn=0x" + c.hrasconn.ToInt64().ToString("X") + " guidEntry=" + c.guidEntry + "\n");
        r.Append("  RasEnumConnectionsW rc=" + erc + " (dwSize " + ConnSize + ")\n");
        RASCONNSTATUSW s0 = new RASCONNSTATUSW(); s0.dwSize = Marshal.SizeOf(typeof(RASCONNSTATUSW));
        int src = RasGetConnectStatusW(hc, ref s0);
        r.Append("  RasGetConnectStatusW at 1 s: rc=" + src + " state=" + s0.rasconnstate + " error=" + s0.dwError + " device=\"" + s0.szDeviceName + "\" phone=\"" + s0.szPhoneNumber + "\"\n");
      }
      if (netstat && el > 1500 && el < 6000 && ports.Length == 0) { string n = Netstat(""); if (!n.StartsWith("(no")) ports = n; }
      if (lastError != 0 || lastState == 0x2000 || lastState == 0x2001) break;
      if (hangupAfterMs > 0 && el >= hangupAfterMs) { r.Append("  hanging up during the dial at " + el + " ms (last state " + lastState + ")\n"); break; }
      if (el >= timeoutMs) { r.Append("  timeout at " + el + " ms (last state " + lastState + ")\n"); break; }
      Thread.Sleep(50);
    }
    if (netstat) r.Append("  TCP towards 192.0.2.1 while dialling: " + (ports.Length == 0 ? "(none seen)" : ports) + "\n");
    long tEnd = Clock.ElapsedMilliseconds - t0;
    if (lastError != 0) r.Append("  dial failed after " + tEnd + " ms: error " + lastError + " (0x" + lastError.ToString("X8") + ") = " + ErrText(lastError) + "\n");
    r.Append("  callback handle 0x" + cbHandle.ToInt64().ToString("X") + " vs RasDialW handle 0x" + hc.ToInt64().ToString("X") + "\n");
    int hr = RasHangUpW(hc);
    long th = Clock.ElapsedMilliseconds;
    int st2 = 0; long gone = -1;
    while (Clock.ElapsedMilliseconds - th < 15000) {
      RASCONNSTATUSW s = new RASCONNSTATUSW(); s.dwSize = Marshal.SizeOf(typeof(RASCONNSTATUSW));
      st2 = RasGetConnectStatusW(hc, ref s);
      if (st2 == 6) { gone = Clock.ElapsedMilliseconds - th; break; }
      Thread.Sleep(10);
    }
    r.Append("  RasHangUpW rc=" + hr + "; RasGetConnectStatusW -> " + (gone >= 0 ? "ERROR_INVALID_HANDLE after " + gone + " ms" : "still rc=" + st2 + " after 15 s") + "\n");
    int erc2; int left = 0;
    foreach (RASCONNW c in Connections(out erc2)) if (c.szEntryName == name) left++;
    r.Append("  connections of this entry left after hang-up: " + left + "\n");
    Thread.Sleep(500);
    r.Append(Drain());
    return r.ToString();
  }
}
'@

function Section([string]$File, [string]$Name) {
  if (-not (Test-Path $File)) { return $null }
  $bytes = [IO.File]::ReadAllBytes($File)
  if ($bytes.Length -ge 2 -and $bytes[0] -eq 0xFF -and $bytes[1] -eq 0xFE) { $text = [Text.Encoding]::Unicode.GetString($bytes, 2, $bytes.Length - 2) }
  else { $text = [Text.Encoding]::Default.GetString($bytes) }
  $lines = $text -split "`r?`n"
  $out = New-Object Collections.Generic.List[string]
  $in = $false
  foreach ($l in $lines) {
    if ($l -match '^\[(.*)\]\s*$') { if ($in) { break }; $in = ($Matches[1] -eq $Name) }
    if ($in) { $out.Add($l) }
  }
  while ($out.Count -gt 0 -and $out[$out.Count - 1] -eq '') { $out.RemoveAt($out.Count - 1) }
  # Unrolled, so `Section ... | Where-Object` filters lines (the wrapped array made it one item: run 3 found that).
  return $out.ToArray()
}

function Encoding-Of([string]$File) {
  $b = [IO.File]::ReadAllBytes($File)
  if ($b.Length -ge 2 -and $b[0] -eq 0xFF -and $b[1] -eq 0xFE) { 'UTF-16LE with BOM' }
  elseif ($b.Length -ge 3 -and $b[0] -eq 0xEF -and $b[1] -eq 0xBB) { 'UTF-8 with BOM' } else { 'ANSI / ASCII (no BOM)' }
}

function Contains-Secret([string]$File, [string]$Secret) {
  $b = [IO.File]::ReadAllBytes($File)
  $hay8 = [Text.Encoding]::GetEncoding(28591).GetString($b)
  $u16 = [Text.Encoding]::GetEncoding(28591).GetString([Text.Encoding]::Unicode.GetBytes($Secret))
  return ($hay8.Contains($Secret) -or $hay8.Contains($u16))
}

function Decode-Policy([string]$Hex) {
  $Hex = $Hex.Trim()
  $bytes = for ($i = 0; $i -lt $Hex.Length; $i += 2) { [Convert]::ToByte($Hex.Substring($i, 2), 16) }
  $dw = for ($i = 0; $i + 3 -lt $bytes.Count; $i += 4) { [BitConverter]::ToUInt32([byte[]]$bytes[$i..($i + 3)], 0) }
  "{0} bytes, DWORDs (LE): {1}" -f $bytes.Count, (($dw | ForEach-Object { $_ }) -join ', ')
}

$Pbk = $env:APPDATA + '\Microsoft\Network\Connections\Pbk\rasphone.pbk'

function Capture {
  Log "== capture (reference entries via Add-VpnConnection, current user's default phonebook) =="
  $fixDir = Join-Path $Out 'fixtures'
  New-Item -ItemType Directory -Force -Path $fixDir | Out-Null
  $existedBefore = Test-Path $Pbk
  $fields = Join-Path $fixDir 'ras_entry_fields.txt'
  "# RASENTRYW fields (non-zero) of Microsoft's reference entries, read back with RasGetEntryPropertiesW. Written by scripts/ras-spike.ps1 capture." | Set-Content -Encoding UTF8 $fields
  $server = 'vpn.example.com'
  $refs = @(
    @{ f = 'l2tp_psk'; a = @{ TunnelType = 'L2tp'; L2tpPsk = $DummyPsk; AuthenticationMethod = 'MSChapv2'; EncryptionLevel = 'Required'; Force = $true } },
    @{ f = 'l2tp_psk_split'; a = @{ TunnelType = 'L2tp'; L2tpPsk = $DummyPsk; AuthenticationMethod = 'MSChapv2'; EncryptionLevel = 'Required'; Force = $true; SplitTunneling = $true } },
    @{ f = 'sstp'; a = @{ TunnelType = 'Sstp'; AuthenticationMethod = 'MSChapv2' } },
    @{ f = 'sstp_split'; a = @{ TunnelType = 'Sstp'; AuthenticationMethod = 'MSChapv2'; SplitTunneling = $true } },
    @{ f = 'sstp_port'; s = 'vpn.example.com:8443'; a = @{ TunnelType = 'Sstp'; AuthenticationMethod = 'MSChapv2' } },
    @{ f = 'ikev2_eap'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'Eap' } },
    @{ f = 'ikev2_eap_split'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'Eap'; SplitTunneling = $true } },
    @{ f = 'ikev2_psk'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'PSK'; L2tpPsk = $DummyPsk; Force = $true } },
    @{ f = 'ikev2_machinecert'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'MachineCertificate' } },
    @{ f = 'ikev2_policy'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'Eap' };
       p = @{ AuthenticationTransformConstants = 'SHA256128'; CipherTransformConstants = 'AES256'; DHGroup = 'Group14'; EncryptionMethod = 'AES256'; IntegrityCheckMethod = 'SHA256'; PfsGroup = 'None' } },
    @{ f = 'ikev2_policy_gcm'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'Eap' };
       p = @{ AuthenticationTransformConstants = 'GCMAES256'; CipherTransformConstants = 'GCMAES256'; DHGroup = 'ECP384'; EncryptionMethod = 'GCMAES256'; IntegrityCheckMethod = 'SHA384'; PfsGroup = 'ECP384' } },
    @{ f = 'ikev2_policy_3des'; a = @{ TunnelType = 'Ikev2'; AuthenticationMethod = 'Eap' };
       p = @{ AuthenticationTransformConstants = 'SHA196'; CipherTransformConstants = 'DES3'; DHGroup = 'Group2'; EncryptionMethod = 'DES3'; IntegrityCheckMethod = 'SHA1'; PfsGroup = 'PFS2048' } }
  )
  $n = 0
  foreach ($r in $refs) {
    $n++
    $name = "WinVPN-spike-$n"
    if ((Test-Path $Pbk) -and (Section $Pbk $name)) { Log "REFUSED: an entry named $name already exists in the default phonebook"; continue }
    $srv = if ($r.s) { $r.s } else { $server }
    $a = $r.a
    try {
      Add-VpnConnection -Name $name -ServerAddress $srv @a -WarningAction SilentlyContinue
      if ($r.p) { $p = $r.p; Set-VpnConnectionIPsecConfiguration -ConnectionName $name @p -Force -WarningAction SilentlyContinue }
    } catch { Log ("{0}: Add-VpnConnection/Set-VpnConnectionIPsecConfiguration failed: {1}" -f $r.f, $_.Exception.Message); try { Remove-VpnConnection -Name $name -Force -ea SilentlyContinue } catch {}; continue }
    $sec = Section $Pbk $name
    $e = [Ras]::NewEntry(); $rc = [Ras]::GetEntry([NullString]::Value, $name, [ref]$e)
    Log ("{0} ({1}): section {2} lines, RasGetEntryPropertiesW rc={3}" -f $r.f, $name, $sec.Count, $rc)
    $leak = Contains-Secret $Pbk $DummyPsk
    Log ("  dummy PSK in the phonebook file: {0}" -f $leak)
    if ($leak) { Log "  NOT WRITING the fixture (secret present)" } else {
      ($sec -join "`r`n") + "`r`n" | Set-Content -Encoding ASCII -NoNewline (Join-Path $fixDir ($r.f + '.pbk'))
    }
    Add-Content -Encoding UTF8 $fields ("[{0}] {1} server={2}`n{3}" -f $r.f, (($a.GetEnumerator() | Sort-Object Name | ForEach-Object { if ($_.Name -eq 'L2tpPsk') { 'L2tpPsk=<dummy>' } else { '{0}={1}' -f $_.Name, $_.Value } }) -join ' '), $srv, [Ras]::Describe($e))
    if ($r.p) { $pol = (Get-VpnConnection -Name $name).IPsecCustomPolicy; Log ("  IPsecCustomPolicy read back: {0}" -f ($pol | Out-String).Trim()) }
  }
  # The fields file as committed: UTF-8 without BOM, LF.
  [IO.File]::WriteAllText($fields, ((Get-Content -Raw $fields) -replace "`r`n", "`n"), (New-Object Text.UTF8Encoding $false))
  Log ("default phonebook encoding: {0}" -f (Encoding-Of $Pbk))
  Get-VpnConnection | Where-Object { $_.Name -like 'WinVPN-spike-*' } | ForEach-Object { Remove-VpnConnection -Name $_.Name -Force }
  $left = @(Get-VpnConnection | Where-Object { $_.Name -like 'WinVPN-spike-*' }).Count
  Log ("WinVPN-spike-* entries left after Remove-VpnConnection: {0}" -f $left)
  if (-not $existedBefore -and (Test-Path $Pbk)) {
    $rest = (Get-Content $Pbk | Where-Object { $_ -match '^\[' }).Count
    if ($rest -eq 0) { Remove-Item $Pbk; Log "removed the default phonebook file this run created (no entries left)" }
  }
}

function New-PrivateDir([string]$Dir) {
  # The data directory's private ACL (2a): the user and SYSTEM, full control, inherited, nothing from the parent.
  New-Item -ItemType Directory -Force -Path $Dir | Out-Null
  $me = [Security.Principal.WindowsIdentity]::GetCurrent().User.Value
  foreach ($d in @((Split-Path $Dir), $Dir)) {
    & icacls.exe $d /inheritance:r /grant:r "*${me}:(OI)(CI)F" '*S-1-5-18:(OI)(CI)F' | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "icacls failed on $d" }
  }
}

function Probe {
  Log "== probe (private phonebook) =="
  $id = [Security.Principal.WindowsIdentity]::GetCurrent()
  $logon = if ($id.Groups | Where-Object { $_.Value -eq 'S-1-5-4' }) { 'INTERACTIVE' } elseif ($id.Groups | Where-Object { $_.Value -eq 'S-1-5-2' }) { 'NETWORK (SSH)' } else { '?' }
  Log ("user {0}, logon {1}, admin {2}" -f $id.Name, $logon, ([Security.Principal.WindowsPrincipal]$id).IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator))
  $root = Join-Path $env:LOCALAPPDATA 'WinVPN-spike'
  $dir = Join-Path $root 'ras'
  New-PrivateDir $dir
  $pp = Join-Path $dir 'spike.pbk'
  Log ("private phonebook: {0} (exists before the first write: {1})" -f $pp, (Test-Path $pp))
  Log ("ACL: {0}" -f (((Get-Acl $dir).Access | ForEach-Object { '{0}:{1}' -f $_.IdentityReference, $_.FileSystemRights }) -join '; '))
  Log ("sizes: RASENTRYW={0} RASDIALPARAMSW={1} RASCONNW={2} RASCONNSTATUSW={3} RASENTRYNAMEW={4} RASCREDENTIALSW={5}" -f [Runtime.InteropServices.Marshal]::SizeOf([type][Ras+RASENTRYW]), [Runtime.InteropServices.Marshal]::SizeOf([type][Ras+RASDIALPARAMSW]), [Runtime.InteropServices.Marshal]::SizeOf([type][Ras+RASCONNW]), [Runtime.InteropServices.Marshal]::SizeOf([type][Ras+RASCONNSTATUSW]), [Runtime.InteropServices.Marshal]::SizeOf([type][Ras+RASENTRYNAMEW]), [Runtime.InteropServices.Marshal]::SizeOf([type][Ras+RASCREDENTIALSW]))

  $names = @{}
  foreach ($k in @('l2tp', 'l2tphang', 'sstp', 'sstpreq', 'sstp8443', 'ikev2eap', 'ikev2hang', 'ikev2psk', 'ikev2pskcert', 'ikev2cert', 'devtest')) { $names[$k] = 'WinVPN-' + [Guid]::NewGuid().ToString().ToUpper() }
  $created = New-Object Collections.Generic.List[string]
  try {
    # --- 11: the device name ---
    Log "-- check 11: device name --"
    $devs = [Ras]::Devices()
    Log ("RasEnumDevicesW: {0}" -f ($devs -join ' || '))
    $rcv = [Ras]::RasValidateEntryNameW($pp, $names.devtest)
    Log ("RasValidateEntryNameW(private, {0} [{1} chars]) before the file exists = {2}" -f $names.devtest, $names.devtest.Length, $rcv)
    $rc = [Ras]::SetEntry($pp, $names.devtest, [Ras]::PlanEntry('l2tp', $Unreachable, $true, ''))
    Log ("RasSetEntryPropertiesW L2TP with empty szDeviceName, szDeviceType=vpn: rc={0} {1}" -f $rc, $(if ($rc) { [Ras]::ErrText($rc) }))
    if ($rc -eq 0) {
      $created.Add($names.devtest)
      $e = [Ras]::NewEntry(); [void][Ras]::GetEntry($pp, $names.devtest, [ref]$e)
      Log ("  read back: szDeviceName=""{0}"" szDeviceType=""{1}""" -f $e.szDeviceName, $e.szDeviceType)
      Log ("  section: {0}" -f ((Section $pp $names.devtest | Where-Object { $_ -match '^(Device|DEVICE|MEDIA|Port)=' }) -join ' | '))
      Log ("  private phonebook encoding: {0}" -f (Encoding-Of $pp))
    }
    $rcv = [Ras]::RasValidateEntryNameW($pp, $names.devtest)
    Log ("RasValidateEntryNameW of the existing name = {0} (183 = ERROR_ALREADY_EXISTS)" -f $rcv)
    Log ("RasValidateEntryNameW(private, 'bad\name') = {0}" -f [Ras]::RasValidateEntryNameW($pp, 'bad\name'))
    $rc = [Ras]::SetEntry($pp, $names.devtest, [Ras]::PlanEntry('l2tp', $Unreachable, $true, 'No Such Device'))
    Log ("RasSetEntryPropertiesW L2TP with szDeviceName='No Such Device': rc={0} {1}; stored Device: {2}" -f $rc, $(if ($rc) { [Ras]::ErrText($rc) }), ((Section $pp $names.devtest | Where-Object { $_ -match '^Device=' }) -join ' | '))

    # --- 1a: which RASENTRYW fields an IKEv2 entry refuses (ERROR_INVALID_PARAMETER) ---
    Log "-- check 1a: IKEv2 field matrix (RasSetEntryPropertiesW rc per variant) --"
    $mx = $names.devtest
    foreach ($variant in @('minimal', '+RequireDataEncryption', '+RequireMsEncryptedPw', '+RequireEncryptedPw', '+ET_Require', '+ET_RequireMax', '+ET_Optional',
        '+RequireEAP', '+RequireEAP+CustomAuthKey26', '+RequireMsCHAP2', '+DontNegotiateMultilink', '+ReconnectIfDropped', '+RemoteDefaultGateway',
        '+IPv6RemoteDefaultGateway', '+UsePreSharedKeyForIkev2Initiator', '+RequireMachineCertificates', '+PlumbIKEv2TSAsRoutes', '+DialMode1', '+Redial3/60', '+NetProtocols IP|IPv6')) {
      $e = [Ras]::NewEntry()
      $e.dwType = 2; $e.dwFramingProtocol = 1; $e.szDeviceType = 'vpn'; $e.szLocalPhoneNumber = $Unreachable; $e.dwVpnStrategy = 7
      switch ($variant) {
        '+RequireDataEncryption' { $e.dwfOptions = 0x1000 } '+RequireMsEncryptedPw' { $e.dwfOptions = 0x800 } '+RequireEncryptedPw' { $e.dwfOptions = 0x400 }
        '+ET_Require' { $e.dwEncryptionType = 1 } '+ET_RequireMax' { $e.dwEncryptionType = 2 } '+ET_Optional' { $e.dwEncryptionType = 3 }
        '+RequireEAP' { $e.dwfOptions = 0x20000 } '+RequireEAP+CustomAuthKey26' { $e.dwfOptions = 0x20000; $e.dwCustomAuthKey = 26 } '+RequireMsCHAP2' { $e.dwfOptions = 0x20000000 }
        '+DontNegotiateMultilink' { $e.dwfOptions2 = 0x4 } '+ReconnectIfDropped' { $e.dwfOptions2 = 0x100 } '+RemoteDefaultGateway' { $e.dwfOptions = 0x10 }
        '+IPv6RemoteDefaultGateway' { $e.dwfOptions2 = 0x2000 } '+UsePreSharedKeyForIkev2Initiator' { $e.dwfOptions2 = 0x800000 } '+RequireMachineCertificates' { $e.dwfOptions2 = 0x400000 }
        '+PlumbIKEv2TSAsRoutes' { $e.dwfOptions2 = [uint32]2147483648 } '+DialMode1' { $e.dwDialMode = 1 } '+Redial3/60' { $e.dwRedialCount = 3; $e.dwRedialPause = 60 } '+NetProtocols IP|IPv6' { $e.dwfNetProtocols = 12 }
      }
      [void][Ras]::RasDeleteEntryW($pp, $mx)
      $rc = [Ras]::SetEntry($pp, $mx, $e)
      Log ("  {0}: rc={1}" -f $variant, $rc)
    }
    # With an authentication method present (EAP), each other field on top; then the PSK combinations.
    foreach ($variant in @('eap', 'eap+RequireDataEncryption', 'eap+ET_Require', 'eap+ET_RequireMax', 'eap+ET_Optional', 'eap+CustomAuthKey26', 'eap+DontNegotiateMultilink',
        'eap+ReconnectIfDropped', 'eap+RemoteDefaultGateway', 'eap+IPv6RemoteDefaultGateway', 'eap+PlumbIKEv2TSAsRoutes', 'eap+DialMode1', 'eap+Redial3/60', 'eap+NetProtocols IP|IPv6',
        'eap+RequireMsEncryptedPw', 'eap+RequireMsCHAP2', 'eap+IPv4ExplicitMetric9000', 'eap+DisableIKEv2Fragmentation', 'cert+ET_RequireMax',
        'psk-initiator', 'psk-initiator+responder', 'psk-initiator+eap', 'psk-initiator+cert', 'psk-initiator+RequireMsCHAP2', 'psk-initiator+RequirePAP', 'psk-initiator+UsePreSharedKey', 'psk-initiator+CustomAuthKey26')) {
      $e = [Ras]::NewEntry()
      $e.dwType = 2; $e.dwFramingProtocol = 1; $e.szDeviceType = 'vpn'; $e.szLocalPhoneNumber = $Unreachable; $e.dwVpnStrategy = 7
      $o = [uint32]0; $o2 = [uint32]0
      if ($variant -like 'eap*') { $o = $o -bor 0x20000 }
      if ($variant -like 'cert*') { $o2 = $o2 -bor 0x400000 }
      if ($variant -like 'psk-initiator*') { $o2 = $o2 -bor 0x800000 }
      switch -Wildcard ($variant) {
        '*+RequireDataEncryption' { $o = $o -bor 0x1000 } '*+ET_Require' { $e.dwEncryptionType = 1 } '*+ET_RequireMax' { $e.dwEncryptionType = 2 } '*+ET_Optional' { $e.dwEncryptionType = 3 }
        '*+CustomAuthKey26' { $e.dwCustomAuthKey = 26 } '*+DontNegotiateMultilink' { $o2 = $o2 -bor 0x4 } '*+ReconnectIfDropped' { $o2 = $o2 -bor 0x100 }
        '*+RemoteDefaultGateway' { $o = $o -bor 0x10 } '*+IPv6RemoteDefaultGateway' { $o2 = $o2 -bor 0x2000 } '*+PlumbIKEv2TSAsRoutes' { $o2 = $o2 -bor [uint32]2147483648 }
        '*+DialMode1' { $e.dwDialMode = 1 } '*+Redial3/60' { $e.dwRedialCount = 3; $e.dwRedialPause = 60 } '*+NetProtocols IP|IPv6' { $e.dwfNetProtocols = 12 }
        '*+RequireMsEncryptedPw' { $o = $o -bor 0x800 } '*+RequireMsCHAP2' { $o = $o -bor 0x20000000 } '*+IPv4ExplicitMetric9000' { $o2 = $o2 -bor 0x10000; $e.dwIPv4InterfaceMetric = 9000 }
        '*+DisableIKEv2Fragmentation' { $e.fDisableIKEv2Fragmentation = 1 } '*+responder' { $o2 = $o2 -bor 0x1000000 } '*+eap' { $o = $o -bor 0x20000 } '*+cert' { $o2 = $o2 -bor 0x400000 }
        '*+RequirePAP' { $o = $o -bor 0x40000 } '*+UsePreSharedKey' { $o2 = $o2 -bor 0x10 }
      }
      $e.dwfOptions = $o; $e.dwfOptions2 = $o2
      [void][Ras]::RasDeleteEntryW($pp, $mx)
      $rc = [Ras]::SetEntry($pp, $mx, $e)
      Log ("  {0}: rc={1}" -f $variant, $rc)
    }
    [void][Ras]::RasDeleteEntryW($pp, $mx)
    [void][Ras]::SetEntry($pp, $mx, [Ras]::PlanEntry('l2tp', $Unreachable, $true, ''))

    # --- 1: entries in the private phonebook ---
    Log "-- check 1: RasSetEntryPropertiesW / RasGetEntryPropertiesW in the private phonebook --"
    $plans = [ordered]@{ l2tp = @('l2tp', $Unreachable, 'l2tp_psk'); l2tphang = @('l2tp', $Unreachable, 'l2tp_psk'); ikev2hang = @('ikev2eap', $Unreachable, 'ikev2_eap'); sstp = @('sstp', $Unreachable, 'sstp'); sstp8443 = @('sstp', "$($Unreachable):8443", 'sstp_port');
      ikev2eap = @('ikev2eap', $Unreachable, 'ikev2_eap'); ikev2psk = @('ikev2psk', $Unreachable, 'ikev2_psk'); ikev2pskcert = @('ikev2pskcert', $Unreachable, 'ikev2_psk'); ikev2cert = @('ikev2cert', $Unreachable, 'ikev2_machinecert') }
    foreach ($k in $plans.Keys) {
      $p = $plans[$k]
      $rc = [Ras]::SetEntry($pp, $names[$k], [Ras]::PlanEntry($p[0], $p[1], $true, ''))
      Log ("{0}: set rc={1} {2}" -f $k, $rc, $(if ($rc) { [Ras]::ErrText($rc) }))
      if ($rc -ne 0) { continue }
      $created.Add($names[$k])
      if ($p[0] -like 'ikev2eap' -or $p[0] -like 'ikev2psk') {
        # EAP-MSCHAPv2 configuration as Add-VpnConnection -AuthenticationMethod Eap writes it: RasSetCustomAuthDataW
        # adds the "1DBC" header (EAP type 26, length) and a zero terminator itself, so only the 8-byte payload is passed.
        $blob = [byte[]](1, 0, 0, 0, 0, 0, 0, 0)
        $crc = [Ras]::RasSetCustomAuthDataW($pp, $names[$k], $blob, $blob.Length)
        $line = (Section $pp $names[$k] | Where-Object { $_ -match '^CustomAuthData=' }) -join ''
        Log ("  RasSetCustomAuthDataW(8-byte payload) rc={0}; {1}; equals the reference: {2}" -f $crc, $line, ($line -eq 'CustomAuthData=314442431A00000008000000010000000000000000000000'))
      }
      $e = [Ras]::NewEntry(); $grc = [Ras]::GetEntry($pp, $names[$k], [ref]$e)
      Log ("  get rc={0}; fields read back:`n{1}" -f $grc, [Ras]::Describe($e))
      $sec = Section $pp $names[$k]
      ($sec -join "`r`n") | Set-Content -Encoding ASCII (Join-Path $Out ("private_{0}.pbk" -f $k))
      if ($Fixtures -and (Test-Path (Join-Path $Fixtures ($p[2] + '.pbk')))) {
        $ref = Get-Content (Join-Path $Fixtures ($p[2] + '.pbk'))
        $d = Compare-Object -ReferenceObject @($ref | Select-Object -Skip 1) -DifferenceObject @($sec | Select-Object -Skip 1) -SyncWindow 500
        Log ("  differences to the reference {0}.pbk (<= reference only, => WinVPN-written only):" -f $p[2])
        foreach ($x in $d) { Log ("    {0} {1}" -f $x.SideIndicator, $x.InputObject) }
      }
    }

    $rc = [Ras]::SetEntry($pp, $names.sstpreq, [Ras]::Plan('sstp', $Unreachable, $true, '', $true))
    if ($rc -eq 0) { $created.Add($names.sstpreq) }
    Log ("sstpreq (SSTP with ET_Require + RASEO_RequireDataEncryption): set rc={0}; DataEncryption line: {1}" -f $rc, ((Section $pp $names.sstpreq | Where-Object { $_ -match '^DataEncryption=' }) -join ''))
    $e = [Ras]::Plan('ikev2eap', $Unreachable, $true, '', $true)
    $rc = [Ras]::SetEntry($pp, $names.devtest, $e)
    Log ("IKEv2 EAP with ET_Require + RASEO_RequireDataEncryption: set rc={0}" -f $rc)
    [void][Ras]::SetEntry($pp, $names.devtest, [Ras]::PlanEntry('l2tp', $Unreachable, $true, ''))
    $e = [Ras]::Plan('ikev2eap', $Unreachable, $false, '', $false); $e.dwfOptions2 = $e.dwfOptions2 -bor [uint32]2147483648
    $rc = [Ras]::SetEntry($pp, $names.devtest, $e)
    Log ("IKEv2 EAP split + RASEO2_PlumbIKEv2TSAsRoutes: set rc={0}; line: {1}" -f $rc, ((Section $pp $names.devtest | Where-Object { $_ -match '^PlumbIKEv2TSAsRoutes=' }) -join ''))
    $e = [Ras]::Plan('sstp', $Unreachable, $true, '', $true); $e.dwfOptions2 = $e.dwfOptions2 -bor 0x30000; $e.dwIPv4InterfaceMetric = 9000; $e.dwIPv6InterfaceMetric = 9000
    $rc = [Ras]::SetEntry($pp, $names.devtest, $e)
    Log ("SSTP + RASEO2_IPv4/IPv6ExplicitMetric 9000: set rc={0}; lines: {1}" -f $rc, ((Section $pp $names.devtest | Where-Object { $_ -match 'InterfaceMetric=' }) -join ' '))
    [void][Ras]::SetEntry($pp, $names.devtest, [Ras]::PlanEntry('l2tp', $Unreachable, $true, ''))

    # --- 5 + 6: the IPsec policy keys ---
    Log "-- checks 5/6: NumCustomPolicy / CustomIPSecPolicies --"
    $polHex = $null
    if ($Fixtures) {
      foreach ($f in @('ikev2_policy', 'ikev2_policy_gcm', 'ikev2_policy_3des')) {
        $fp = Join-Path $Fixtures "$f.pbk"
        if (Test-Path $fp) {
          $line = Get-Content $fp | Where-Object { $_ -match '^CustomIPSecPolicies=' }
          $num = Get-Content $fp | Where-Object { $_ -match '^NumCustomPolicy=' }
          if ($line) { $hex = $line.Substring(20); Log ("{0}: {1}; CustomIPSecPolicies={2}; {3}" -f $f, $num, $hex, (Decode-Policy $hex)); if (-not $polHex) { $polHex = $hex } }
          else { Log "${f}: no CustomIPSecPolicies key" }
        }
      }
    }
    if (-not $polHex) {
      # The plan's assumed layout for policy 1 (six DWORDs: integrity SHA256=2? ...) is not used blind: without a
      # reference the check only tests whether the keys survive a rewrite.
      $polHex = '0102030405060708090A0B0C0D0E0F101112131415161718'
      Log "no reference policy (run capture first); using a placeholder value to test persistence only"
    }
    if ($created.Contains($names.ikev2eap)) {
      $n = $names.ikev2eap
      [void][Ras]::WritePrivateProfileStringW($n, 'NumCustomPolicy', '1', $pp)
      [void][Ras]::WritePrivateProfileStringW($n, 'CustomIPSecPolicies', $polHex, $pp)
      $sb = New-Object Text.StringBuilder 1024
      [void][Ras]::GetPrivateProfileStringW($n, 'CustomIPSecPolicies', '<none>', $sb, 1024, $pp)
      Log ("written and re-read: CustomIPSecPolicies={0} (equal: {1})" -f $sb, ($sb.ToString() -eq $polHex))
      $e = [Ras]::NewEntry(); [void][Ras]::GetEntry($pp, $n, [ref]$e)
      $rc = [Ras]::SetEntry($pp, $n, $e)
      $sb2 = New-Object Text.StringBuilder 1024; [void][Ras]::GetPrivateProfileStringW($n, 'CustomIPSecPolicies', '<none>', $sb2, 1024, $pp)
      $sb3 = New-Object Text.StringBuilder 64; [void][Ras]::GetPrivateProfileStringW($n, 'NumCustomPolicy', '<none>', $sb3, 64, $pp)
      Log ("after RasSetEntryPropertiesW with the entry read back (rc={0}): NumCustomPolicy={1} CustomIPSecPolicies={2}" -f $rc, $sb3, $sb2)
      $rc = [Ras]::SetEntry($pp, $n, [Ras]::PlanEntry('ikev2eap', $Unreachable, $true, ''))
      $sb2 = New-Object Text.StringBuilder 1024; [void][Ras]::GetPrivateProfileStringW($n, 'CustomIPSecPolicies', '<none>', $sb2, 1024, $pp)
      $sb3 = New-Object Text.StringBuilder 64; [void][Ras]::GetPrivateProfileStringW($n, 'NumCustomPolicy', '<none>', $sb3, 64, $pp)
      Log ("after RasSetEntryPropertiesW with a fresh RASENTRYW (rc={0}): NumCustomPolicy={1} CustomIPSecPolicies={2}" -f $rc, $sb3, $sb2)
      # Rewritten once more so the dial below uses the policy.
      [void][Ras]::WritePrivateProfileStringW($n, 'NumCustomPolicy', '1', $pp)
      [void][Ras]::WritePrivateProfileStringW($n, 'CustomIPSecPolicies', $polHex, $pp)
      Log ("private phonebook encoding after WritePrivateProfileStringW: {0}" -f (Encoding-Of $pp))
    }

    # --- 4: the PSK store ---
    Log "-- check 4: RasSetCredentialsW(RASCM_PreSharedKey) / RasGetCredentialsW --"
    $n = $names.l2tp
    Log ("before: {0}" -f [Ras]::GetCreds($pp, $n, [Ras]::RASCM_PreSharedKey))
    $rc = [Ras]::SetPsk($pp, $n, $DummyPsk, $false)
    Log ("RasSetCredentialsW(PSK) rc={0} {1}" -f $rc, $(if ($rc) { [Ras]::ErrText($rc) }))
    Log ("after set: {0}" -f [Ras]::GetCreds($pp, $n, [Ras]::RASCM_PreSharedKey))
    Log ("dummy PSK in the private phonebook file: {0}" -f (Contains-Secret $pp $DummyPsk))
    [void][Ras]::SetPsk($pp, $names.ikev2pskcert, $DummyPsk, $false)
    $rcI = [Ras]::SetPsk($pp, $names.ikev2psk, $DummyPsk, $false)
    Log ("RasSetCredentialsW(PSK) on the IKEv2 PSK entry rc={0}; read: {1}" -f $rcI, [Ras]::GetCreds($pp, $names.ikev2psk, [Ras]::RASCM_PreSharedKey))
    $e = [Ras]::NewEntry(); [void][Ras]::GetEntry($pp, $n, [ref]$e)
    [void][Ras]::SetEntry($pp, $n, $e)
    Log ("after rewriting the entry with RasSetEntryPropertiesW: {0}" -f [Ras]::GetCreds($pp, $n, [Ras]::RASCM_PreSharedKey))
    $rc = [Ras]::RasDeleteEntryW($pp, $n)
    $rc2 = [Ras]::SetEntry($pp, $n, [Ras]::PlanEntry('l2tp', $Unreachable, $true, ''))
    Log ("RasDeleteEntryW rc={0}, re-created rc={1}; PSK after delete + re-create: {2}" -f $rc, $rc2, [Ras]::GetCreds($pp, $n, [Ras]::RASCM_PreSharedKey))
    $rc = [Ras]::SetPsk($pp, $n, $DummyPsk, $false)
    $rcC = [Ras]::SetPsk($pp, $n, '', $true)
    Log ("set again rc={0}; fClearCredentials rc={1}; after clear: {2}" -f $rc, $rcC, [Ras]::GetCreds($pp, $n, [Ras]::RASCM_PreSharedKey))
    Log ("password store (RASCM_UserName|RASCM_Password) of the entry: {0}" -f [Ras]::GetCreds($pp, $n, ([Ras]::RASCM_UserName -bor [Ras]::RASCM_Password)))
    [void][Ras]::SetPsk($pp, $n, $DummyPsk, $false)  # for the dial below

    # --- 8: enumeration of the default phonebooks ---
    Log "-- check 8: RasEnumEntriesW --"
    $defName = 'WinVPN-spike-x-' + [Guid]::NewGuid().ToString('N').Substring(0, 8)
    $defExisted = Test-Path $Pbk
    $rc = [Ras]::SetEntry([NullString]::Value, $defName, [Ras]::PlanEntry('sstp', 'vpn.example.com', $true, ''))
    Log ("default phonebook entry {0}: set rc={1} {2} (file existed before: {3})" -f $defName, $rc, $(if ($rc) { [Ras]::ErrText($rc) }), $defExisted)
    $erc = 0
    foreach ($x in [Ras]::Entries([NullString]::Value, [ref]$erc)) { Log ("  RasEnumEntriesW(NULL, NULL): {0}" -f $x) }
    Log ("  rc={0}" -f $erc)
    foreach ($x in [Ras]::Entries($pp, [ref]$erc)) { Log ("  RasEnumEntriesW(NULL, private): {0}" -f $x) }
    Log ("  rc={0}" -f $erc)
    if ($rc -eq 0) {
      $e = [Ras]::NewEntry(); [void][Ras]::GetEntry([NullString]::Value, $defName, [ref]$e)
      Log ("  default entry guidId={0}" -f $e.guidId)
      $drc = [Ras]::RasDeleteEntryW([NullString]::Value, $defName)
      Log ("  deleted rc={0}" -f $drc)
      if (-not $defExisted -and (Test-Path $Pbk) -and -not (Get-Content $Pbk | Where-Object { $_ -match '^\[' })) { Remove-Item $Pbk; Log "  removed the default phonebook file this run created" }
    }

    # --- 2, 3, 7, 9, 10: dialling 192.0.2.1 ---
    if ($SkipDial) { Log "-- dials skipped (-SkipDial) --"; return }
    Log "-- checks 2/3/7/9/10: RasDialW against 192.0.2.1 (TEST-NET-1) --"
    $nrc = [Ras]::StartNotifications()
    Log ("RasConnectionNotificationW(INVALID_HANDLE_VALUE) rc={0}" -f $nrc)
    $dials = @(
      @('l2tp', $DummyUser, $DummyPassword, 0, $false),
      @('sstp', $DummyUser, $DummyPassword, 0, $true),
      @('sstp8443', $DummyUser, $DummyPassword, 0, $true),
      @('ikev2eap', $DummyUser, $DummyPassword, 0, $false),
      @('ikev2psk', '', '', 0, $false),
      @('ikev2pskcert', '', '', 0, $false),
      @('sstpreq', $DummyUser, $DummyPassword, 0, $false),
      @('ikev2cert', '', '', 0, $false),
      @('l2tphang', $DummyUser, $DummyPassword, 3000, $false),
      @('ikev2hang', $DummyUser, $DummyPassword, 3000, $false),
      @('l2tp', $DummyUser, $DummyPassword, 3000, $false)
    )
    foreach ($d in $dials) {
      if (-not $created.Contains($names[$d[0]])) { Log ("{0}: no entry, skipped" -f $d[0]); continue }
      Log ("{0}{1}:" -f $d[0], $(if ($d[3]) { ' (hang-up during the dial at ' + $d[3] + ' ms)' } else { '' }))
      Log ([Ras]::Dial($pp, $names[$d[0]], $d[1], $d[2], 150000, $d[3], $d[4]))
    }
    if ($created.Contains($names.ikev2cert)) {
      # The phonebook path in another letter case: which form does RasEnumConnectionsW report?
      Log ("ikev2cert dialled with the phonebook path in upper case ({0}):" -f $pp.ToUpper())
      Log ([Ras]::Dial($pp.ToUpper(), $names.ikev2cert, '', '', 150000, 0, $false))
    }
    Start-Sleep -Seconds 1
    Log ("late events:`n{0}" -f [Ras]::Drain())
    [Ras]::StopNotifications()
  } finally {
    Log "-- cleanup --"
    foreach ($n in $created) {
      [void][Ras]::SetPsk($pp, $n, '', $true)
      Log ("delete {0}: rc={1}" -f $n, [Ras]::RasDeleteEntryW($pp, $n))
    }
    Log ("private phonebook sections left: {0}" -f $(if (Test-Path $pp) { (Get-Content $pp | Where-Object { $_ -match '^\[' }).Count } else { 'file gone' }))
    Remove-Item -Recurse -Force $root -ErrorAction SilentlyContinue
    Log ("removed {0}: {1}" -f $root, (-not (Test-Path $root)))
  }
}

$k = Get-ItemProperty 'HKLM:\SOFTWARE\Microsoft\Windows NT\CurrentVersion'
Log ("== ras-spike {0} on {1} {2} build {3}.{4}, UI {5}, {6} ==" -f $Mode, $k.EditionID, $k.DisplayVersion, $k.CurrentBuild, $k.UBR, (Get-UICulture).Name, (Get-Date -Format s))
if ($Mode -eq 'capture' -or $Mode -eq 'all') { Capture }
if ($Mode -eq 'all' -and -not $Fixtures) { $Fixtures = Join-Path $Out 'fixtures' }
if ($Mode -eq 'probe' -or $Mode -eq 'all') { Probe }
Log '== done =='
