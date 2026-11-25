using System.Diagnostics;
using System.Net;
using System.Runtime.InteropServices;

namespace NetSnitch.Services;

public record RawSocketRow(
    string Protocol,
    string LocalIp,
    int LocalPort,
    string RemoteIp,
    int RemotePort,
    string State,
    int Pid
);

public static class NativeNetworkApi
{
    private const int AF_INET = 2;
    private const int AF_INET6 = 23;
    private const int TCP_TABLE_OWNER_PID_ALL = 5;
    private const int UDP_TABLE_OWNER_PID = 1;

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedTcpTable(
        IntPtr pTcpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", SetLastError = true)]
    private static extern uint GetExtendedUdpTable(
        IntPtr pUdpTable,
        ref int pdwSize,
        bool bOrder,
        int ulAf,
        int tableClass,
        uint reserved = 0);

    [DllImport("iphlpapi.dll", ExactSpelling = true)]
    private static extern int SendARP(uint destIp, uint srcIp, byte[] macAddr, ref int physicalAddrLen);

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCPROW_OWNER_PID
    {
        public uint dwState;
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public uint dwRemoteAddr;
        public uint dwRemotePort;
        public int dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_TCP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucRemoteAddr;
        public uint dwRemoteScopeId;
        public uint dwRemotePort;
        public uint dwState;
        public int dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDPROW_OWNER_PID
    {
        public uint dwLocalAddr;
        public uint dwLocalPort;
        public int dwOwningPid;
    }

    [StructLayout(LayoutKind.Sequential)]
    private struct MIB_UDP6ROW_OWNER_PID
    {
        [MarshalAs(UnmanagedType.ByValArray, SizeConst = 16)]
        public byte[] ucLocalAddr;
        public uint dwLocalScopeId;
        public uint dwLocalPort;
        public int dwOwningPid;
    }

    private static ushort ConvertPort(uint rawPort) =>
        (ushort)(((rawPort & 0xFF) << 8) | ((rawPort & 0xFF00) >> 8));

    private static string MapTcpState(uint state) => state switch
    {
        1 => "CLOSED",
        2 => "LISTEN",
        3 => "SYN_SENT",
        4 => "SYN_RCVD",
        5 => "ESTABLISHED",
        6 => "FIN_WAIT1",
        7 => "FIN_WAIT2",
        8 => "CLOSE_WAIT",
        9 => "CLOSING",
        10 => "LAST_ACK",
        11 => "TIME_WAIT",
        12 => "DELETE_TCB",
        _ => "UNKNOWN"
    };

    public static List<RawSocketRow> GetAllSockets()
    {
        var result = new List<RawSocketRow>(256);
        ReadTcpV4(result);
        ReadTcpV6(result);
        ReadUdpV4(result);
        ReadUdpV6(result);
        return result;
    }

    private static void ReadTcpV4(List<RawSocketRow> list)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL);
        if (size <= 0) return;

        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(ptr, ref size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL) != 0)
                return;

            int count = Marshal.ReadInt32(ptr);
            IntPtr rowPtr = ptr + 4;
            int rowSize = Marshal.SizeOf<MIB_TCPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCPROW_OWNER_PID>(rowPtr);
                list.Add(new RawSocketRow(
                    "TCP",
                    new IPAddress(row.dwLocalAddr).ToString(),
                    ConvertPort(row.dwLocalPort),
                    new IPAddress(row.dwRemoteAddr).ToString(),
                    ConvertPort(row.dwRemotePort),
                    MapTcpState(row.dwState),
                    row.dwOwningPid));
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    private static void ReadTcpV6(List<RawSocketRow> list)
    {
        int size = 0;
        GetExtendedTcpTable(IntPtr.Zero, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL);
        if (size <= 0) return;

        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedTcpTable(ptr, ref size, false, AF_INET6, TCP_TABLE_OWNER_PID_ALL) != 0)
                return;

            int count = Marshal.ReadInt32(ptr);
            IntPtr rowPtr = ptr + 4;
            int rowSize = Marshal.SizeOf<MIB_TCP6ROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_TCP6ROW_OWNER_PID>(rowPtr);
                list.Add(new RawSocketRow(
                    "TCPv6",
                    new IPAddress(row.ucLocalAddr).ToString(),
                    ConvertPort(row.dwLocalPort),
                    new IPAddress(row.ucRemoteAddr).ToString(),
                    ConvertPort(row.dwRemotePort),
                    MapTcpState(row.dwState),
                    row.dwOwningPid));
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    private static void ReadUdpV4(List<RawSocketRow> list)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET, UDP_TABLE_OWNER_PID);
        if (size <= 0) return;

        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(ptr, ref size, false, AF_INET, UDP_TABLE_OWNER_PID) != 0)
                return;

            int count = Marshal.ReadInt32(ptr);
            IntPtr rowPtr = ptr + 4;
            int rowSize = Marshal.SizeOf<MIB_UDPROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDPROW_OWNER_PID>(rowPtr);
                list.Add(new RawSocketRow(
                    "UDP",
                    new IPAddress(row.dwLocalAddr).ToString(),
                    ConvertPort(row.dwLocalPort),
                    "*",
                    0,
                    "LISTEN",
                    row.dwOwningPid));
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    private static void ReadUdpV6(List<RawSocketRow> list)
    {
        int size = 0;
        GetExtendedUdpTable(IntPtr.Zero, ref size, false, AF_INET6, UDP_TABLE_OWNER_PID);
        if (size <= 0) return;

        IntPtr ptr = Marshal.AllocHGlobal(size);
        try
        {
            if (GetExtendedUdpTable(ptr, ref size, false, AF_INET6, UDP_TABLE_OWNER_PID) != 0)
                return;

            int count = Marshal.ReadInt32(ptr);
            IntPtr rowPtr = ptr + 4;
            int rowSize = Marshal.SizeOf<MIB_UDP6ROW_OWNER_PID>();
            for (int i = 0; i < count; i++)
            {
                var row = Marshal.PtrToStructure<MIB_UDP6ROW_OWNER_PID>(rowPtr);
                list.Add(new RawSocketRow(
                    "UDPv6",
                    new IPAddress(row.ucLocalAddr).ToString(),
                    ConvertPort(row.dwLocalPort),
                    "*",
                    0,
                    "LISTEN",
                    row.dwOwningPid));
                rowPtr += rowSize;
            }
        }
        finally { Marshal.FreeHGlobal(ptr); }
    }

    public static string? ResolveMacViaArp(IPAddress ip)
    {
        if (ip.AddressFamily != System.Net.Sockets.AddressFamily.InterNetwork) return null;
        byte[] bytes = ip.GetAddressBytes();
        uint destIp = BitConverter.ToUInt32(bytes, 0);
        byte[] mac = new byte[6];
        int len = mac.Length;
        if (SendARP(destIp, 0, mac, ref len) == 0 && len == 6)
        {
            return string.Join(":", mac.Select(b => b.ToString("X2")));
        }
        return null;
    }

    public static (string Name, string Path) GetProcessInfo(int pid)
    {
        if (pid <= 0) return ("System Idle", "");
        if (pid == 4) return ("System", "ntoskrnl.exe");
        try
        {
            using var proc = Process.GetProcessById(pid);
            string name = proc.ProcessName + ".exe";
            string path = "";
            try { path = proc.MainModule?.FileName ?? ""; } catch { }
            return (name, path);
        }
        catch
        {
            return ($"pid:{pid}", "");
        }
    }
}
