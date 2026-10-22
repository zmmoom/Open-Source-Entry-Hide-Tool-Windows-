// DeviceLink.cs
// 自研 Apple 设备连接助手（STA 线程 + Windows 消息泵）。
// 与第三方 iFineOpenHide 同源：直接 P/Invoke 苹果官方 MobileDevice.dll，
// 在真正的 STA 线程上 Subscribe，回调内 CreateCopy -> Connect -> Pair -> Session。
// 代码为从零编写，仅调用 Apple 官方 API，不含任何第三方专有代码。
//
// 用法：
//   DeviceLink.exe [AppleDLL目录]
// 成功时 stdout 输出一行 JSON：
//   {"ok":true,"udid":"....","paired":true,"session":true}
// 失败：
//   {"ok":false,"error":"...."}
// 退出码：0=成功，1=无设备/失败。

using System;
using System.Runtime.InteropServices;
using System.Text;

namespace DeviceLink
{
    internal static class Native
    {
        // ── kernel32 ──
        [DllImport("kernel32.dll", CharSet = CharSet.Unicode, SetLastError = true)]
        public static extern bool SetDllDirectoryW(string lpPathName);

        // ── CoreFoundation ──
        [DllImport("CoreFoundation.dll")]
        public static extern IntPtr CFStringCreateWithCString(
            IntPtr alloc, string cstr, uint encoding);

        [DllImport("CoreFoundation.dll")]
        public static extern bool CFStringGetCString(
            IntPtr cfstr, StringBuilder buffer, int bufferSize, uint encoding);

        [DllImport("CoreFoundation.dll")]
        public static extern void CFRelease(IntPtr cf);

        [DllImport("CoreFoundation.dll")]
        public static extern int CFArrayGetCount(IntPtr array);

        [DllImport("CoreFoundation.dll")]
        public static extern IntPtr CFArrayGetValueAtIndex(IntPtr array, int idx);

        // ── MobileDevice ──
        [DllImport("MobileDevice.dll", EntryPoint = "AMDCreateDeviceList")]
        public static extern IntPtr CreateDeviceList();

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceNotificationSubscribe")]
        public static extern int NotificationSubscribe(
            NotificationCallback callback, uint unused0, uint fireNow,
            uint unused1, out IntPtr subscription);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceNotificationUnsubscribe")]
        public static extern int NotificationUnsubscribe(IntPtr subscription);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceCreateCopy")]
        public static extern IntPtr CreateCopy(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceConnect")]
        public static extern int Connect(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceDisconnect")]
        public static extern int Disconnect(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceIsPaired")]
        public static extern int IsPaired(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDevicePair")]
        public static extern int Pair(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceValidatePairing")]
        public static extern int ValidatePairing(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceStartSession")]
        public static extern int StartSession(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceStopSession")]
        public static extern int StopSession(IntPtr device);

        [DllImport("MobileDevice.dll", EntryPoint = "AMDeviceCopyValue")]
        public static extern IntPtr CopyValue(IntPtr device, IntPtr domain, IntPtr key);

        // ── user32（原生 Windows 消息泵，等价 .NET STA 自带泵）──
        [StructLayout(LayoutKind.Sequential)]
        public struct MSG
        {
            public IntPtr hwnd;
            public uint message;
            public IntPtr wParam;
            public IntPtr lParam;
            public uint time;
            public int pt_x;
            public int pt_y;
        }

        [DllImport("user32.dll")]
        public static extern bool PeekMessage(out MSG msg, IntPtr hwnd, uint min, uint max, uint remove);

        [DllImport("user32.dll")]
        public static extern bool TranslateMessage(ref MSG msg);

        [DllImport("user32.dll")]
        public static extern IntPtr DispatchMessage(ref MSG msg);

        public const uint PM_REMOVE = 1;
        public const uint kCFStringEncodingUTF8 = 0x08000100;
    }

    [StructLayout(LayoutKind.Sequential)]
    internal struct NotificationInfo
    {
        public IntPtr device;
        public uint message;
    }

    internal delegate void NotificationCallback(ref NotificationInfo info, IntPtr arg);

    internal static class Program
    {
        private static readonly object _gate = new object();
        private static bool _done = false;
        private static string _udid = "";
        private static bool _paired = false;
        private static bool _sessionOk = false;
        private static string _error = "";

        // 必须保持委托存活，防止 GC 回收导致原生回调崩溃。
        private static NotificationCallback _cb;

        [STAThread]
        private static int Main(string[] args)
        {
            // ① 定位并锁定 Apple DLL 目录。
            string dllDir = args.Length > 0 ? args[0] : null;
            if (!string.IsNullOrEmpty(dllDir))
            {
                Native.SetDllDirectoryW(dllDir);
                string path = Environment.GetEnvironmentVariable("PATH") ?? "";
                Environment.SetEnvironmentVariable("PATH", dllDir + ";" + path);
            }

            // ② 订阅设备通知（fire_now=1，已连接设备会立即补发）。
            IntPtr sub;
            _cb = new NotificationCallback(OnNotification);
            int rc = Native.NotificationSubscribe(_cb, 0, 1, 0, out sub);
            if (rc != 0)
            {
                EmitFail("AMDeviceNotificationSubscribe=0x" + rc.ToString("x"));
                return 1;
            }

            // ③ 兜底：同步枚举一次（应对补发延迟）。
            try
            {
                IntPtr arr = Native.CreateDeviceList();
                if (arr != IntPtr.Zero)
                {
                    int n = Native.CFArrayGetCount(arr);
                    for (int i = 0; i < n; i++)
                    {
                        IntPtr dev = Native.CFArrayGetValueAtIndex(arr, i);
                        if (dev != IntPtr.Zero)
                            HandleDevice(dev);
                    }
                    Native.CFRelease(arr);
                }
            }
            catch (Exception e)
            {
                SetError("CreateDeviceList: " + e.Message);
            }

            // ④ 原生 Windows 消息泵（等同 .NET STA 泵），驱动 Apple 回调。
            DateTime deadline = DateTime.UtcNow.AddSeconds(15);
            while (!IsDone() && DateTime.UtcNow < deadline)
            {
                Native.MSG msg;
                if (Native.PeekMessage(out msg, IntPtr.Zero, 0, 0, Native.PM_REMOVE))
                {
                    Native.TranslateMessage(ref msg);
                    Native.DispatchMessage(ref msg);
                }
                else
                {
                    System.Threading.Thread.Sleep(20);
                }
            }

            try { Native.NotificationUnsubscribe(sub); } catch { }

            if (IsDone() && _sessionOk)
            {
                Console.WriteLine("{\"ok\":true,\"udid\":\"" + JsonEscape(_udid)
                    + "\",\"paired\":" + (_paired ? "true" : "false")
                    + ",\"session\":true}");
                return 0;
            }
            EmitFail(string.IsNullOrEmpty(_error) ? "15 秒内未完成设备连接/会话" : _error);
            return 1;
        }

        private static void OnNotification(ref NotificationInfo info, IntPtr arg)
        {
            // message: 1=connected, 2=disconnected（不同版本可能不同，只处理非空设备）
            if (info.device != IntPtr.Zero)
                HandleDevice(info.device);
        }

        private static void HandleDevice(IntPtr rawDevice)
        {
            try
            {
                IntPtr dev = Native.CreateCopy(rawDevice);
                if (dev == IntPtr.Zero)
                    dev = rawDevice;

                string udid = CopyString(dev, "UniqueDeviceID");
                if (!string.IsNullOrEmpty(udid))
                    _udid = udid;

                // Connect（带与第三方一致的简单重试）
                int err = Native.Connect(dev);
                if (err != 0)
                {
                    for (int i = 0; i < 2 && err != 0; i++)
                    {
                        try { Native.Disconnect(dev); } catch { }
                        System.Threading.Thread.Sleep(350);
                        err = Native.Connect(dev);
                    }
                }
                if (err != 0)
                {
                    SetError("AMDeviceConnect=0x" + err.ToString("x"));
                    return;
                }

                // 配对
                bool paired = Native.IsPaired(dev) == 1;
                if (!paired)
                {
                    int pe = Native.Pair(dev);
                    paired = (pe == 0);
                }
                _paired = paired;
                if (paired)
                {
                    try { Native.ValidatePairing(dev); } catch { }
                }

                // 会话
                int se = Native.StartSession(dev);
                if (se != 0)
                {
                    for (int i = 0; i < 2 && se != 0; i++)
                    {
                        try { Native.StopSession(dev); } catch { }
                        try { Native.Disconnect(dev); } catch { }
                        System.Threading.Thread.Sleep(450);
                        Native.Connect(dev);
                        se = Native.StartSession(dev);
                    }
                }
                _sessionOk = (se == 0);
                if (se != 0)
                {
                    SetError("AMDeviceStartSession=0x" + se.ToString("x"));
                    return;
                }

                // 本助手只负责把"连接+配对+会话"跑通并证明成功；
                // 配对记录已持久化，随即收尾，不占用设备。
                try { Native.StopSession(dev); } catch { }
                try { Native.Disconnect(dev); } catch { }

                MarkDone();
            }
            catch (Exception e)
            {
                SetError("HandleDevice: " + e.Message);
            }
        }

        private static string CopyString(IntPtr dev, string key)
        {
            IntPtr keyRef = Native.CFStringCreateWithCString(
                IntPtr.Zero, key, Native.kCFStringEncodingUTF8);
            try
            {
                IntPtr valRef = Native.CopyValue(dev, IntPtr.Zero, keyRef);
                if (valRef == IntPtr.Zero)
                    return null;
                try
                {
                    var sb = new StringBuilder(512);
                    if (Native.CFStringGetCString(valRef, sb, sb.Capacity,
                            Native.kCFStringEncodingUTF8))
                        return sb.ToString();
                    return null;
                }
                finally
                {
                    Native.CFRelease(valRef);
                }
            }
            finally
            {
                Native.CFRelease(keyRef);
            }
        }

        private static void MarkDone() { lock (_gate) { _done = true; } }
        private static bool IsDone() { lock (_gate) { return _done; } }
        private static void SetError(string s) { lock (_gate) { if (string.IsNullOrEmpty(_error)) _error = s; } }

        private static void EmitFail(string err)
        {
            Console.WriteLine("{\"ok\":false,\"error\":\"" + JsonEscape(err) + "\"}");
        }

        private static string JsonEscape(string s)
        {
            if (s == null) return "";
            var sb = new StringBuilder();
            foreach (char c in s)
            {
                switch (c)
                {
                    case '\\': sb.Append("\\\\"); break;
                    case '"': sb.Append("\\\""); break;
                    case '\n': sb.Append("\\n"); break;
                    case '\r': sb.Append("\\r"); break;
                    case '\t': sb.Append("\\t"); break;
                    default:
                        if (c < 0x20) sb.Append("\\u" + ((int)c).ToString("x4"));
                        else sb.Append(c);
                        break;
                }
            }
            return sb.ToString();
        }
    }
}
