using System.IO;
using System.Net.Sockets;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;

namespace NetSnitch.Services;

public sealed class RfbClient : IDisposable
{
    private TcpClient? _tcp;
    private NetworkStream? _stream;
    private CancellationTokenSource? _cts;

    public int Width { get; private set; }
    public int Height { get; private set; }
    public string DesktopName { get; private set; } = string.Empty;
    public bool IsConnected => _tcp?.Connected == true;

    public event Action<int, int, int, int, byte[]>? OnRectUpdated;
    public event Action<int, int>? OnDesktopResized;
    public event Action<string>? OnDisconnected;

    public async Task ConnectAsync(string host, int port, string? username, string? password, CancellationToken ct)
    {
        _tcp = new TcpClient { NoDelay = true };
        await _tcp.ConnectAsync(host, port, ct).ConfigureAwait(false);
        _stream = _tcp.GetStream();

        // 1. Handshake version
        byte[] verBuf = await ReadExactAsync(12, ct).ConfigureAwait(false);
        string serverVer = Encoding.ASCII.GetString(verBuf);
        if (!serverVer.StartsWith("RFB "))
            throw new InvalidOperationException($"Неверный ответ сервера: {serverVer}");

        await _stream.WriteAsync(Encoding.ASCII.GetBytes("RFB 003.008\n"), ct).ConfigureAwait(false);

        // 2. Security types
        int numTypes = await ReadByteAsync(ct).ConfigureAwait(false);
        if (numTypes == 0)
        {
            string reason = await ReadReasonAsync(ct).ConfigureAwait(false);
            throw new InvalidOperationException($"Сервер отклонил подключение: {reason}");
        }

        byte[] types = await ReadExactAsync(numTypes, ct).ConfigureAwait(false);
        byte chosenType = ChooseSecurityType(types, username);
        await _stream.WriteAsync(new[] { chosenType }, ct).ConfigureAwait(false);

        switch (chosenType)
        {
            case 1: // None
                break;
            case 2: // VNC Auth (DES)
                await AuthenticateVncAsync(password ?? "", ct).ConfigureAwait(false);
                break;
            case 30: // Apple Remote Desktop DH
                await AuthenticateAppleDhAsync(username ?? "", password ?? "", ct).ConfigureAwait(false);
                break;
            default:
                throw new NotSupportedException($"Неподдерживаемый метод аутентификации RFB: {string.Join(",", types)}");
        }

        // SecurityResult
        uint secResult = await ReadUInt32BeAsync(ct).ConfigureAwait(false);
        if (secResult != 0)
        {
            string reason = await TryReadReasonAsync(ct).ConfigureAwait(false);
            throw new UnauthorizedAccessException($"Ошибка входа ARD/VNC: {reason}");
        }

        // 3. ClientInit (shared = 1)
        await _stream.WriteAsync(new byte[] { 1 }, ct).ConfigureAwait(false);

        // 4. ServerInit
        Width = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
        Height = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
        _ = await ReadExactAsync(16, ct).ConfigureAwait(false); // Server PixelFormat
        uint nameLen = await ReadUInt32BeAsync(ct).ConfigureAwait(false);
        if (nameLen > 0 && nameLen < 4096)
        {
            byte[] nameBytes = await ReadExactAsync((int)nameLen, ct).ConfigureAwait(false);
            DesktopName = Encoding.UTF8.GetString(nameBytes);
        }

        // SetPixelFormat: 32bpp, depth 24, little-endian, true-color, BGRA (for WPF Bgra32)
        byte[] setPf =
        [
            0, 0, 0, 0,       // msg-type 0 + 3 pad
            32, 24, 0, 1,     // bpp=32, depth=24, big-endian=0, true-color=1
            0, 255, 0, 255, 0, 255, // max R, G, B = 255
            16, 8, 0,         // R shift=16, G shift=8, B shift=0 (BGRA)
            0, 0, 0           // padding
        ];
        await _stream.WriteAsync(setPf, ct).ConfigureAwait(false);

        // SetEncodings: Raw (0), CopyRect (1), DesktopSize (-223)
        byte[] setEnc = new byte[4 + 3 * 4];
        setEnc[0] = 2; // msg-type 2
        setEnc[2] = 0; setEnc[3] = 3; // 3 encodings
        WriteInt32Be(setEnc, 4, 0);    // Raw
        WriteInt32Be(setEnc, 8, 1);    // CopyRect
        WriteInt32Be(setEnc, 12, -223); // DesktopSize
        await _stream.WriteAsync(setEnc, ct).ConfigureAwait(false);

        _cts = new CancellationTokenSource();
        _ = Task.Run(() => ReceiveLoopAsync(_cts.Token));
        await RequestFramebufferUpdateAsync(incremental: false).ConfigureAwait(false);
    }

    private static byte ChooseSecurityType(byte[] types, string? username)
    {
        if (!string.IsNullOrWhiteSpace(username) && types.Contains((byte)30)) return 30;
        if (types.Contains((byte)2)) return 2;
        if (types.Contains((byte)30)) return 30;
        if (types.Contains((byte)1)) return 1;
        return types.FirstOrDefault();
    }

    private async Task AuthenticateVncAsync(string password, CancellationToken ct)
    {
        byte[] challenge = await ReadExactAsync(16, ct).ConfigureAwait(false);
        byte[] key = new byte[8];
        byte[] pwBytes = Encoding.ASCII.GetBytes(password);
        for (int i = 0; i < Math.Min(8, pwBytes.Length); i++)
            key[i] = ReverseBits(pwBytes[i]);

        using var des = DES.Create();
        des.Mode = CipherMode.ECB;
        des.Padding = PaddingMode.None;
        des.Key = key;

        using var enc = des.CreateEncryptor();
        byte[] response = enc.TransformFinalBlock(challenge, 0, 16);
        await _stream!.WriteAsync(response, ct).ConfigureAwait(false);
    }

    private async Task AuthenticateAppleDhAsync(string username, string password, CancellationToken ct)
    {
        // Server sends: generator (2), keyLength (2), prime (keyLen), serverPublicKey (keyLen)
        ushort gen = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
        ushort keyLen = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
        byte[] primeBytes = await ReadExactAsync(keyLen, ct).ConfigureAwait(false);
        byte[] pubBytes = await ReadExactAsync(keyLen, ct).ConfigureAwait(false);

        var p = new BigInteger(primeBytes, isUnsigned: true, isBigEndian: true);
        var g = new BigInteger(gen);
        var serverPub = new BigInteger(pubBytes, isUnsigned: true, isBigEndian: true);

        byte[] privBuf = RandomNumberGenerator.GetBytes(keyLen);
        var priv = new BigInteger(privBuf, isUnsigned: true, isBigEndian: true);
        var clientPub = BigInteger.ModPow(g, priv, p);
        var shared = BigInteger.ModPow(serverPub, priv, p);

        byte[] clientPubBytes = PadBigEndian(clientPub, keyLen);
        byte[] sharedBytes = PadBigEndian(shared, keyLen);
        byte[] aesKey = MD5.HashData(sharedBytes);

        // Plaintext: 64 bytes username + 64 bytes password (null-padded)
        byte[] plain = new byte[128];
        byte[] uBytes = Encoding.UTF8.GetBytes(username);
        byte[] pBytes = Encoding.UTF8.GetBytes(password);
        Array.Copy(uBytes, 0, plain, 0, Math.Min(64, uBytes.Length));
        Array.Copy(pBytes, 0, plain, 64, Math.Min(64, pBytes.Length));

        using var aes = Aes.Create();
        aes.Mode = CipherMode.ECB;
        aes.Padding = PaddingMode.None;
        aes.Key = aesKey;
        using var encryptor = aes.CreateEncryptor();
        byte[] cipher = encryptor.TransformFinalBlock(plain, 0, 128);

        byte[] payload = new byte[128 + keyLen];
        Array.Copy(cipher, 0, payload, 0, 128);
        Array.Copy(clientPubBytes, 0, payload, 128, keyLen);
        await _stream!.WriteAsync(payload, ct).ConfigureAwait(false);
    }

    private async Task ReceiveLoopAsync(CancellationToken ct)
    {
        try
        {
            while (!ct.IsCancellationRequested && _stream != null)
            {
                int msgType = await ReadByteAsync(ct).ConfigureAwait(false);
                if (msgType == 0) // FramebufferUpdate
                {
                    _ = await ReadByteAsync(ct).ConfigureAwait(false); // padding
                    ushort rectCount = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
                    for (int i = 0; i < rectCount; i++)
                    {
                        ushort x = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
                        ushort y = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
                        ushort w = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
                        ushort h = await ReadUInt16BeAsync(ct).ConfigureAwait(false);
                        int enc = (int)await ReadUInt32BeAsync(ct).ConfigureAwait(false);

                        if (enc == 0) // Raw
                        {
                            byte[] pixels = await ReadExactAsync(w * h * 4, ct).ConfigureAwait(false);
                            OnRectUpdated?.Invoke(x, y, w, h, pixels);
                        }
                        else if (enc == 1) // CopyRect
                        {
                            _ = await ReadExactAsync(4, ct).ConfigureAwait(false);
                        }
                        else if (enc == -223) // DesktopSize
                        {
                            Width = w;
                            Height = h;
                            OnDesktopResized?.Invoke(w, h);
                        }
                    }

                    await RequestFramebufferUpdateAsync(incremental: true).ConfigureAwait(false);
                }
                else if (msgType == 2) // Bell
                {
                }
                else if (msgType == 3) // ServerCutText
                {
                    _ = await ReadExactAsync(3, ct).ConfigureAwait(false);
                    uint len = await ReadUInt32BeAsync(ct).ConfigureAwait(false);
                    if (len > 0 && len < 1_000_000)
                        _ = await ReadExactAsync((int)len, ct).ConfigureAwait(false);
                }
            }
        }
        catch (Exception ex) when (!ct.IsCancellationRequested)
        {
            OnDisconnected?.Invoke(ex.Message);
        }
    }

    public async Task RequestFramebufferUpdateAsync(bool incremental)
    {
        if (_stream == null || !IsConnected) return;
        byte[] req = new byte[10];
        req[0] = 3; // FramebufferUpdateRequest
        req[1] = (byte)(incremental ? 1 : 0);
        WriteUInt16Be(req, 6, (ushort)Width);
        WriteUInt16Be(req, 8, (ushort)Height);
        await _stream.WriteAsync(req).ConfigureAwait(false);
    }

    public async Task SendPointerEventAsync(byte buttonMask, int x, int y)
    {
        if (_stream == null || !IsConnected) return;
        byte[] msg = new byte[6];
        msg[0] = 5;
        msg[1] = buttonMask;
        WriteUInt16Be(msg, 2, (ushort)Math.Clamp(x, 0, Math.Max(0, Width - 1)));
        WriteUInt16Be(msg, 4, (ushort)Math.Clamp(y, 0, Math.Max(0, Height - 1)));
        try { await _stream.WriteAsync(msg).ConfigureAwait(false); } catch { }
    }

    public async Task SendKeyEventAsync(bool down, uint keysym)
    {
        if (_stream == null || !IsConnected) return;
        byte[] msg = new byte[8];
        msg[0] = 4;
        msg[1] = (byte)(down ? 1 : 0);
        WriteInt32Be(msg, 4, (int)keysym);
        try { await _stream.WriteAsync(msg).ConfigureAwait(false); } catch { }
    }

    private async Task<int> ReadByteAsync(CancellationToken ct)
    {
        byte[] b = await ReadExactAsync(1, ct).ConfigureAwait(false);
        return b[0];
    }

    private async Task<ushort> ReadUInt16BeAsync(CancellationToken ct)
    {
        byte[] b = await ReadExactAsync(2, ct).ConfigureAwait(false);
        return (ushort)((b[0] << 8) | b[1]);
    }

    private async Task<uint> ReadUInt32BeAsync(CancellationToken ct)
    {
        byte[] b = await ReadExactAsync(4, ct).ConfigureAwait(false);
        return (uint)((b[0] << 24) | (b[1] << 16) | (b[2] << 8) | b[3]);
    }

    private async Task<byte[]> ReadExactAsync(int count, CancellationToken ct)
    {
        byte[] buf = new byte[count];
        int offset = 0;
        while (offset < count)
        {
            int read = await _stream!.ReadAsync(buf.AsMemory(offset, count - offset), ct).ConfigureAwait(false);
            if (read == 0) throw new EndOfStreamException("Соединение закрыто удалённым хостом.");
            offset += read;
        }
        return buf;
    }

    private async Task<string> ReadReasonAsync(CancellationToken ct)
    {
        uint len = await ReadUInt32BeAsync(ct).ConfigureAwait(false);
        if (len == 0 || len > 4096) return "Unknown";
        byte[] b = await ReadExactAsync((int)len, ct).ConfigureAwait(false);
        return Encoding.UTF8.GetString(b);
    }

    private async Task<string> TryReadReasonAsync(CancellationToken ct)
    {
        try { return await ReadReasonAsync(ct).ConfigureAwait(false); }
        catch { return "Неверный логин или пароль"; }
    }

    private static byte ReverseBits(byte b)
    {
        byte r = 0;
        for (int i = 0; i < 8; i++)
        {
            r = (byte)((r << 1) | (b & 1));
            b >>= 1;
        }
        return r;
    }

    private static byte[] PadBigEndian(BigInteger val, int length)
    {
        byte[] raw = val.ToByteArray(isUnsigned: true, isBigEndian: true);
        if (raw.Length == length) return raw;
        byte[] res = new byte[length];
        if (raw.Length > length)
            Array.Copy(raw, raw.Length - length, res, 0, length);
        else
            Array.Copy(raw, 0, res, length - raw.Length, raw.Length);
        return res;
    }

    private static void WriteUInt16Be(byte[] buf, int offset, ushort val)
    {
        buf[offset] = (byte)(val >> 8);
        buf[offset + 1] = (byte)(val & 0xFF);
    }

    private static void WriteInt32Be(byte[] buf, int offset, int val)
    {
        buf[offset] = (byte)(val >> 24);
        buf[offset + 1] = (byte)(val >> 16);
        buf[offset + 2] = (byte)(val >> 8);
        buf[offset + 3] = (byte)(val & 0xFF);
    }

    public void Dispose()
    {
        _cts?.Cancel();
        _stream?.Dispose();
        _tcp?.Dispose();
    }
}
