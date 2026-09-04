using System.ComponentModel;
using System.Runtime.InteropServices;

internal static class Program
{
    const uint ServiceWin32OwnProcess=0x10, ServiceStartPending=2, ServiceStopPending=3, ServiceRunning=4, ServiceStopped=1, ServiceAcceptStop=1;
    static readonly ManualResetEvent StopSignal=new(false); static readonly ServiceMainCallback ServiceMainDelegate=ServiceMain;static readonly HandlerCallback HandlerDelegate=Handler;static IntPtr _status;
    public static int Main()
    {
        if(Environment.UserInteractive){Console.WriteLine("OpenSecurityPlatform Sprint 8 controlled service fixture");return 0;}
        var table=new[]{new ServiceTableEntry{ServiceName="OpenSecurityPlatformSprint8Fixture",ServiceMain=Marshal.GetFunctionPointerForDelegate(ServiceMainDelegate)},new ServiceTableEntry()};
        if(!StartServiceCtrlDispatcher(table))throw new Win32Exception(Marshal.GetLastWin32Error());return 0;
    }
    static void ServiceMain(int argc,IntPtr argv){_status=RegisterServiceCtrlHandlerEx("OpenSecurityPlatformSprint8Fixture",HandlerDelegate,IntPtr.Zero);if(_status==IntPtr.Zero)return;Report(ServiceStartPending,0);Report(ServiceRunning,ServiceAcceptStop);StopSignal.WaitOne();Report(ServiceStopped,0);}
    static uint Handler(uint control,uint eventType,IntPtr eventData,IntPtr context){if(control==1){Report(ServiceStopPending,0);StopSignal.Set();}return 0;}
    static void Report(uint state,uint accepted){var status=new ServiceStatus{ServiceType=ServiceWin32OwnProcess,CurrentState=state,ControlsAccepted=accepted};SetServiceStatus(_status,ref status);}
    [StructLayout(LayoutKind.Sequential,CharSet=CharSet.Unicode)]struct ServiceTableEntry{[MarshalAs(UnmanagedType.LPWStr)]public string? ServiceName;public IntPtr ServiceMain;}
    [StructLayout(LayoutKind.Sequential)]struct ServiceStatus{public uint ServiceType,CurrentState,ControlsAccepted,Win32ExitCode,ServiceSpecificExitCode,CheckPoint,WaitHint;}
    delegate void ServiceMainCallback(int argc,IntPtr argv);delegate uint HandlerCallback(uint control,uint eventType,IntPtr eventData,IntPtr context);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern bool StartServiceCtrlDispatcher([In]ServiceTableEntry[] table);
    [DllImport("advapi32.dll",SetLastError=true,CharSet=CharSet.Unicode)]static extern IntPtr RegisterServiceCtrlHandlerEx(string name,HandlerCallback callback,IntPtr context);
    [DllImport("advapi32.dll",SetLastError=true)]static extern bool SetServiceStatus(IntPtr handle,ref ServiceStatus status);
}
