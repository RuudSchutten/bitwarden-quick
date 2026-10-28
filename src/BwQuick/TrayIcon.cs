using System.Drawing;
using System.Drawing.Drawing2D;
using System.Drawing.Text;
using System.Windows.Forms;
using BwQuick.Native;

namespace BwQuick;

internal sealed class TrayIcon : IDisposable
{
    private readonly NotifyIcon _icon;
    private readonly ToolStripMenuItem _openItem;
    private readonly ToolStripMenuItem _autostartItem;
    private readonly Icon _image;

    public event Action? OpenRequested;
    public event Action? SyncRequested;
    public event Action? SignOutRequested;
    public event Action? ExitRequested;

    public TrayIcon()
    {
        _image = CreateIcon();
        _openItem = new ToolStripMenuItem("Zoeken", null, (_, _) => OpenRequested?.Invoke()) { Font = new Font(SystemFonts.MenuFont!, System.Drawing.FontStyle.Bold) };
        _autostartItem = new ToolStripMenuItem("Starten met Windows", null, (_, _) =>
        {
            AppSettings.StartWithWindows = !AppSettings.StartWithWindows;
            _autostartItem!.Checked = AppSettings.StartWithWindows;
        });

        var menu = new ContextMenuStrip();
        menu.Items.Add(_openItem);
        menu.Items.Add(new ToolStripMenuItem("Nu synchroniseren", null, (_, _) => SyncRequested?.Invoke()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(_autostartItem);
        menu.Items.Add(new ToolStripMenuItem("Uitloggen en lokale gegevens wissen…", null, (_, _) => SignOutRequested?.Invoke()));
        menu.Items.Add(new ToolStripSeparator());
        menu.Items.Add(new ToolStripMenuItem("Afsluiten", null, (_, _) => ExitRequested?.Invoke()));
        menu.Opening += (_, _) => _autostartItem.Checked = AppSettings.StartWithWindows;

        _icon = new NotifyIcon { Icon = _image, Text = "BwQuick", ContextMenuStrip = menu, Visible = true };
        _icon.MouseClick += (_, e) =>
        {
            if (e.Button == MouseButtons.Left) OpenRequested?.Invoke();
        };
    }

    public void SetHotkeyLabel(string gesture) => _openItem.Text = $"Zoeken ({gesture})";

    public void SetStatus(string text) => _icon.Text = text.Length > 120 ? text[..120] : text;

    public void Notify(string title, string text, bool error = false) =>
        _icon.ShowBalloonTip(4000, title, text, error ? ToolTipIcon.Warning : ToolTipIcon.Info);

    private static Icon CreateIcon()
    {
        using var bmp = new Bitmap(32, 32);
        using (var g = Graphics.FromImage(bmp))
        {
            g.SmoothingMode = SmoothingMode.AntiAlias;
            g.TextRenderingHint = TextRenderingHint.AntiAliasGridFit;
            using var path = new GraphicsPath();
            const int r = 8;
            path.AddArc(0, 0, r * 2, r * 2, 180, 90);
            path.AddArc(31 - r * 2, 0, r * 2, r * 2, 270, 90);
            path.AddArc(31 - r * 2, 31 - r * 2, r * 2, r * 2, 0, 90);
            path.AddArc(0, 31 - r * 2, r * 2, r * 2, 90, 90);
            path.CloseFigure();
            using var fill = new SolidBrush(Color.FromArgb(0x17, 0x5D, 0xDC));
            g.FillPath(fill, path);

            var family = FontFamily.Families.Any(f => f.Name == "Segoe Fluent Icons") ? "Segoe Fluent Icons" : "Segoe MDL2 Assets";
            using var font = new Font(family, 17, GraphicsUnit.Pixel);
            using var format = new StringFormat { Alignment = StringAlignment.Center, LineAlignment = StringAlignment.Center };
            g.DrawString("", font, Brushes.White, new RectangleF(0, 1, 32, 32), format);
        }
        var handle = bmp.GetHicon();
        try
        {
            return (Icon)Icon.FromHandle(handle).Clone();
        }
        finally
        {
            Win32.DestroyIcon(handle);
        }
    }

    public void Dispose()
    {
        _icon.Visible = false;
        _icon.Dispose();
        _image.Dispose();
    }
}
