using System.Windows;
using System.Windows.Input;
using System.Windows.Media;
using System.Windows.Media.Imaging;
using NetSnitch.Services;

namespace NetSnitch;

public partial class ArdViewerWindow : Window
{
    private RfbClient? _client;
    private WriteableBitmap? _bitmap;
    private byte _mouseMask;

    public ArdViewerWindow(string host, int port = 5900)
    {
        InitializeComponent();
        HostBox.Text = host;
        PortBox.Text = port.ToString();
        Closed += (_, _) => _client?.Dispose();
    }

    private async void ConnectBtn_Click(object sender, RoutedEventArgs e)
    {
        if (_client != null)
        {
            _client.Dispose();
            _client = null;
            ConnectBtn.Content = "▶ Подключиться";
            StatusText.Text = "Отключено";
            return;
        }

        string host = HostBox.Text.Trim();
        if (!int.TryParse(PortBox.Text.Trim(), out int port)) port = 5900;
        string user = UserBox.Text.Trim();
        string pass = PassBox.Password;

        ConnectBtn.IsEnabled = false;
        StatusText.Text = $"Подключение к {host}:{port}...";

        try
        {
            var client = new RfbClient();
            client.OnRectUpdated += Client_OnRectUpdated;
            client.OnDesktopResized += Client_OnDesktopResized;
            client.OnDisconnected += reason => Dispatcher.Invoke(() =>
            {
                StatusText.Text = $"Отключено: {reason}";
                ConnectBtn.Content = "▶ Подключиться";
                _client?.Dispose();
                _client = null;
            });

            using var cts = new CancellationTokenSource(8000);
            await client.ConnectAsync(host, port, user, pass, cts.Token);

            _client = client;
            InitBitmap(client.Width, client.Height);
            Title = $"ARD / Screen Sharing — {client.DesktopName} ({host})";
            StatusText.Text = $"Подключено ({client.Width}×{client.Height})";
            ConnectBtn.Content = "■ Отключиться";
        }
        catch (Exception ex)
        {
            StatusText.Text = $"Ошибка: {ex.Message}";
        }
        finally
        {
            ConnectBtn.IsEnabled = true;
        }
    }

    private void InitBitmap(int width, int height)
    {
        if (width <= 0 || height <= 0) return;
        _bitmap = new WriteableBitmap(width, height, 96, 96, PixelFormats.Bgra32, null);
        ScreenImage.Source = _bitmap;
    }

    private void Client_OnDesktopResized(int w, int h)
    {
        Dispatcher.Invoke(() => InitBitmap(w, h));
    }

    private void Client_OnRectUpdated(int x, int y, int w, int h, byte[] pixels)
    {
        Dispatcher.BeginInvoke(() =>
        {
            if (_bitmap == null || x + w > _bitmap.PixelWidth || y + h > _bitmap.PixelHeight) return;
            _bitmap.WritePixels(new Int32Rect(x, y, w, h), pixels, w * 4, 0);
        });
    }

    private (int X, int Y) MapMousePos(MouseEventArgs e)
    {
        if (_bitmap == null || ScreenImage.ActualWidth <= 0 || ScreenImage.ActualHeight <= 0)
            return (0, 0);
        var p = e.GetPosition(ScreenImage);
        int x = (int)(p.X * _bitmap.PixelWidth / ScreenImage.ActualWidth);
        int y = (int)(p.Y * _bitmap.PixelHeight / ScreenImage.ActualHeight);
        return (x, y);
    }

    private void UpdateMouseButtons(MouseEventArgs e)
    {
        byte mask = 0;
        if (e.LeftButton == MouseButtonState.Pressed) mask |= 1;
        if (e.MiddleButton == MouseButtonState.Pressed) mask |= 2;
        if (e.RightButton == MouseButtonState.Pressed) mask |= 4;
        _mouseMask = mask;
    }

    private void ScreenImage_MouseMove(object sender, MouseEventArgs e)
    {
        if (_client == null) return;
        var (x, y) = MapMousePos(e);
        _ = _client.SendPointerEventAsync(_mouseMask, x, y);
    }

    private void ScreenImage_MouseDown(object sender, MouseButtonEventArgs e)
    {
        if (_client == null) return;
        Focus();
        UpdateMouseButtons(e);
        var (x, y) = MapMousePos(e);
        _ = _client.SendPointerEventAsync(_mouseMask, x, y);
    }

    private void ScreenImage_MouseUp(object sender, MouseButtonEventArgs e)
    {
        if (_client == null) return;
        UpdateMouseButtons(e);
        var (x, y) = MapMousePos(e);
        _ = _client.SendPointerEventAsync(_mouseMask, x, y);
    }

    private void ScreenImage_MouseWheel(object sender, MouseWheelEventArgs e)
    {
        if (_client == null) return;
        var (x, y) = MapMousePos(e);
        byte wheelBit = (byte)(e.Delta > 0 ? 8 : 16);
        _ = _client.SendPointerEventAsync((byte)(_mouseMask | wheelBit), x, y);
        _ = _client.SendPointerEventAsync(_mouseMask, x, y);
    }

    private void Window_KeyDown(object sender, KeyEventArgs e) => HandleKey(e, true);
    private void Window_KeyUp(object sender, KeyEventArgs e) => HandleKey(e, false);

    private void HandleKey(KeyEventArgs e, bool down)
    {
        if (_client == null || HostBox.IsFocused || PortBox.IsFocused || UserBox.IsFocused || PassBox.IsFocused)
            return;

        uint keysym = MapKeyToX11Keysym(e.Key);
        if (keysym != 0)
        {
            _ = _client.SendKeyEventAsync(down, keysym);
            e.Handled = true;
        }
    }

    private static uint MapKeyToX11Keysym(Key key) => key switch
    {
        Key.Back => 0xFF08,
        Key.Tab => 0xFF09,
        Key.Return => 0xFF0D,
        Key.Escape => 0xFF1B,
        Key.Delete => 0xFFFF,
        Key.Home => 0xFF50,
        Key.Left => 0xFF51,
        Key.Up => 0xFF52,
        Key.Right => 0xFF53,
        Key.Down => 0xFF54,
        Key.PageUp => 0xFF55,
        Key.PageDown => 0xFF56,
        Key.End => 0xFF57,
        Key.LeftShift or Key.RightShift => 0xFFE1,
        Key.LeftCtrl or Key.RightCtrl => 0xFFE3,
        Key.LeftAlt or Key.RightAlt => 0xFFE9,
        Key.Space => 0x0020,
        >= Key.A and <= Key.Z => (uint)('a' + (key - Key.A)),
        >= Key.D0 and <= Key.D9 => (uint)('0' + (key - Key.D0)),
        _ => 0
    };
}
