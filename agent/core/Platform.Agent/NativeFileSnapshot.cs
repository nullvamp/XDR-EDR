using System.Globalization;
using System.Runtime.InteropServices;
using Microsoft.Win32.SafeHandles;
using OpenSecurityPlatform.Foundation;

sealed record NativeFileSnapshot(
    FileNativeIdentity Identity,
    long Size,
    DateTimeOffset ModifiedAt,
    DateTimeOffset? ChangedAt
)
{
    public string CacheMaterial(string endpointScope, string algorithm) =>
        string.Join(
            '\0',
            endpointScope,
            Identity.VolumeId ?? "",
            Identity.FileId ?? "",
            Identity.DeviceId?.ToString(CultureInfo.InvariantCulture) ?? "",
            Identity.Inode?.ToString(CultureInfo.InvariantCulture) ?? "",
            Identity.MountId?.ToString(CultureInfo.InvariantCulture) ?? "",
            Size.ToString(CultureInfo.InvariantCulture),
            ModifiedAt.UtcTicks.ToString(CultureInfo.InvariantCulture),
            ChangedAt?.UtcTicks.ToString(CultureInfo.InvariantCulture) ?? "",
            algorithm
        );

    public bool SameObject(NativeFileSnapshot other) =>
        Identity.VolumeId == other.Identity.VolumeId
        && Identity.FileId == other.Identity.FileId
        && Identity.DeviceId == other.Identity.DeviceId
        && Identity.Inode == other.Identity.Inode
        && Identity.MountId == other.Identity.MountId;

    public bool SameState(NativeFileSnapshot other) =>
        SameObject(other)
        && Size == other.Size
        && ModifiedAt == other.ModifiedAt
        && ChangedAt == other.ChangedAt;
}

static class NativeFileSnapshotReader
{
    const int AtFdcwd = -100;
    const int AtSymlinkNoFollow = 0x100;
    const uint StatxBasicStats = 0x7ff;
    const uint StatxMntId = 0x1000;

    public static NativeFileSnapshot? TryRead(string path)
    {
        try
        {
            return OperatingSystem.IsWindows() ? ReadWindows(path)
            : OperatingSystem.IsLinux() ? ReadLinux(path)
            : ReadPortable(path);
        }
        catch (Exception e)
            when (e is IOException or UnauthorizedAccessException or NotSupportedException)
        {
            return null;
        }
    }

    static NativeFileSnapshot? ReadWindows(string path)
    {
        var reparsePoint = File.GetAttributes(path).HasFlag(FileAttributes.ReparsePoint);
        using var handle = File.OpenHandle(
            path,
            FileMode.Open,
            FileAccess.Read,
            FileShare.ReadWrite | FileShare.Delete
        );
        if (!GetFileInformationByHandle(handle, out var value))
            throw new IOException($"GetFileInformationByHandle failed: {Marshal.GetLastWin32Error()}");
        var index = ((ulong)value.FileIndexHigh << 32) | value.FileIndexLow;
        var size = ((long)value.FileSizeHigh << 32) | value.FileSizeLow;
        var modified = DateTimeOffset.FromFileTime(
            ((long)value.LastWriteTime.dwHighDateTime << 32)
                | (uint)value.LastWriteTime.dwLowDateTime
        );
        return new(
            new(
                value.VolumeSerialNumber.ToString("x8", CultureInfo.InvariantCulture),
                $"windows:{value.VolumeSerialNumber:x8}:{index:x16}",
                null,
                null,
                null,
                reparsePoint,
                value.NumberOfLinks > 1
            ),
            size,
            modified,
            null
        );
    }

    static NativeFileSnapshot? ReadLinux(string path)
    {
        if (
            statx(
                AtFdcwd,
                path,
                AtSymlinkNoFollow,
                StatxBasicStats | StatxMntId,
                out var value
            ) != 0
        )
            throw new IOException($"statx failed: {Marshal.GetLastPInvokeError()}");
        var modified = FromUnix(value.Modified);
        var changed = FromUnix(value.Changed);
        var device = ((long)value.DeviceMajor << 32) | value.DeviceMinor;
        return new(
            new(
                $"linux-device:{value.DeviceMajor}:{value.DeviceMinor}",
                $"linux:{device}:{value.Inode}",
                device,
                checked((long)value.Inode),
                null,
                (value.Mode & 0xF000) == 0xA000,
                value.LinkCount > 1,
                checked((long)value.MountId)
            ),
            checked((long)value.Size),
            modified,
            changed
        );
    }

    static NativeFileSnapshot? ReadPortable(string path)
    {
        var value = new FileInfo(path);
        value.Refresh();
        if (!value.Exists)
            return null;
        return new(
            new(null, null, null, null, null, value.LinkTarget is not null, null),
            value.Length,
            value.LastWriteTimeUtc,
            null
        );
    }

    static DateTimeOffset FromUnix(StatxTimestamp value) =>
        DateTimeOffset.FromUnixTimeSeconds(value.Seconds).AddTicks(value.Nanoseconds / 100);

    [StructLayout(LayoutKind.Sequential)]
    struct ByHandleFileInformation
    {
        public uint FileAttributes;
        public System.Runtime.InteropServices.ComTypes.FILETIME CreationTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastAccessTime;
        public System.Runtime.InteropServices.ComTypes.FILETIME LastWriteTime;
        public uint VolumeSerialNumber;
        public uint FileSizeHigh;
        public uint FileSizeLow;
        public uint NumberOfLinks;
        public uint FileIndexHigh;
        public uint FileIndexLow;
    }

    [StructLayout(LayoutKind.Sequential)]
    struct StatxTimestamp
    {
        public long Seconds;
        public uint Nanoseconds;
        public int Reserved;
    }

    [StructLayout(LayoutKind.Sequential, Size = 256)]
    struct Statx
    {
        public uint Mask;
        public uint BlockSize;
        public ulong Attributes;
        public uint LinkCount;
        public uint UserId;
        public uint GroupId;
        public ushort Mode;
        public ushort Spare0;
        public ulong Inode;
        public ulong Size;
        public ulong Blocks;
        public ulong AttributesMask;
        public StatxTimestamp Accessed;
        public StatxTimestamp Created;
        public StatxTimestamp Changed;
        public StatxTimestamp Modified;
        public uint RdevMajor;
        public uint RdevMinor;
        public uint DeviceMajor;
        public uint DeviceMinor;
        public ulong MountId;
        public uint DirectIoMemoryAlign;
        public uint DirectIoOffsetAlign;
    }

    [DllImport("kernel32.dll", SetLastError = true)]
    static extern bool GetFileInformationByHandle(
        SafeFileHandle handle,
        out ByHandleFileInformation information
    );

#pragma warning disable CA2101 // LPUTF8Str is required for Linux filesystem paths.
    [DllImport("libc", SetLastError = true, EntryPoint = "statx")]
    static extern int statx(
        int directoryFileDescriptor,
        [MarshalAs(UnmanagedType.LPUTF8Str)] string path,
        int flags,
        uint mask,
        out Statx buffer
    );
#pragma warning restore CA2101
}
