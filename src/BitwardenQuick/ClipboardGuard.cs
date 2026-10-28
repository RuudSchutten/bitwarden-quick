using System.Windows.Threading;
using BitwardenQuick.Native;

namespace BitwardenQuick;

/// <summary>Clears a copied secret after a delay, unless something else was copied in the meantime.</summary>
internal sealed class ClipboardGuard
{
    private readonly Func<nint> _owner;
    private readonly DispatcherTimer _timer = new();
    private uint? _sequence;

    public ClipboardGuard(Func<nint> owner)
    {
        _owner = owner;
        _timer.Tick += (_, _) => ClearNow();
    }

    public void Arm(uint sequence, int seconds)
    {
        _sequence = sequence;
        _timer.Stop();
        _timer.Interval = TimeSpan.FromSeconds(seconds);
        _timer.Start();
    }

    public void ClearNow()
    {
        _timer.Stop();
        if (_sequence is { } sequence) SecureClipboard.ClearIfUnchanged(_owner(), sequence);
        _sequence = null;
    }

    /// <summary>Callable from any thread, for when the process is about to die and the timer with it.</summary>
    public void ClearAfterCrash()
    {
        if (_sequence is { } sequence) SecureClipboard.ClearIfUnchanged(0, sequence);
    }
}
