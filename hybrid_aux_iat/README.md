# PoC code and tools for Hybrid Auxiliary IAT hooking

This directory collects PoC code and tools for Hybrid Auxiliary IAT hooking.

- [arm64ecext](#arm64ecext) is a WinDbg extension for analyzing Hybrid Auxiliary IAT of ARM64EC.
- [HybridAuxIATHooking](#HybridAuxIATHooking) is PoC code for Hybrid Auxiliary IAT hooking.

If you are not familiar with Hybrid Auxiliary IAT and its hooking method, check out [my presentation slides at CODE BLUE 2021]() (slides will be available after my talk.).

## Requirements

- Visual Studio 2019 Preview
- [SDK Insider Preview](https://www.microsoft.com/en-us/software-download/windowsinsiderpreviewSDK)
    - NOTE: To download this, you need to be a member of the Windows Insider program.

You also need to set the active solution platform to ARM64 before building.

## arm64ecext

[arm64ecext](./arm64ecext) is a WinDbg extension for analyzing Hybrid Auxiliary IAT of ARM64EC.

`!arm64ecext.help` shows the usage of this WinDbg extension.

```
0:024:ARM64EC> .load arm64ecext
0:024:ARM64EC> !arm64ecext.help
!dump <image base> - dump the Hybrid Auxiliary IAT of a module
!show <image base> <function name> - show the Hybrid Auxiliary IAT entry of a function
!check <image base> - check whether Hybrid Auxiliary IAT hooking is used
```

### `dump` command

This command shows the Hybrid Auxiliary IAT entries of a specified module.

```
0:024:ARM64EC> !arm64ecext.dump powershell
Image Base is 00007ff76cb50000
Image Import Descriptor is 00007ff76cb68224
Image Load Config Directory is 00007ff76cb661b0
Module: OLE32.dll 00007ffc1f550000
                Name              IAT          Aux IAT     Aux IAT copy
    PropVariantClear 00007ffc1f5527c0 00007ffc1f93ede0 00007ff76cb5c220
      CoUninitialize 00007ffc1f551af0 00007ffc1f819ae0 00007ff76cb5c320
      CoTaskMemAlloc 00007ffc1f5519d0 00007ffc1f81ecf0 00007ff76cb5c260
      CoInitializeEx 00007ffc1f5515a0 00007ffc1f8194c0 00007ff76cb5c5a0
        CoInitialize 00007ffc20fe1100 00007ffc210db8a0 00007ff76cb5c1e0
    CoCreateInstance 00007ffc1f5511c0 00007ffc1f8da770 00007ff76cb5c340

Module: OLEAUT32.dll 00007ffc20490000
                Name              IAT          Aux IAT     Aux IAT copy
           Ordinal_9 00007ffc204929b0 00007ffc205ccba0 00007ff76cb5c180
           Ordinal_7 00007ffc20491700 00007ffc2058c5d0 00007ff76cb5c360
           Ordinal_6 00007ffc204916b0 00007ffc2058c350 00007ff76cb5c4e0
           Ordinal_2 00007ffc20491680 00007ffc2058c1d0 00007ff76cb5c480
          Ordinal_1a 00007ffc204915d0 00007ffc2058b360 00007ff76cb5c460
           Ordinal_f 00007ffc204914c0 00007ffc2058aa10 00007ff76cb5c2e0

Module: ATL.DLL 00007ffc1acf0000
                Name              IAT          Aux IAT     Aux IAT copy
          Ordinal_1e 00007ffc1acf10b0 00007ffc1ad05800 00007ff76cb5c140
...
```

### `show` command

This command shows the Hybrid Auxiliary IAT entry of a specified function name.

```
0:024:ARM64EC> !arm64ecext.show powershell PropVariantClear
Image Base is 00007ff76cb50000
Image Import Descriptor is 00007ff76cb68224
Image Load Config Directory is 00007ff76cb661b0
                Name              IAT          Aux IAT     Aux IAT Copy
    PropVariantClear 00007ffc1f5527c0 00007ffc1f93ede0 00007ff76cb5c220
```

### `check` command

This command shows hooked functions by Hybrid Auxiliary IAT hooking method.

```
0:000:ARM64EC> !arm64ecext.check AuxiliaryIATHook
Image Base is 00007ff6da6f0000
Image Import Descriptor is 00007ff6da6f7bcc
Image Load Config Directory is 00007ff6da6f72f0
Possibly hooked functions
                Name              IAT          Aux IAT     Aux IAT Copy
         MessageBoxA 00007ffc20c73190 00007ff6da6f11e0 00007ff6da6f14a0
```

## HybridAuxIATHooking

[HybridAuxIATHooking](./HybridAuxIATHooking) is PoC code of Hybrid Auxiliary IAT hooking.

**Demo movie**
![Hybrid Auxiliary IAT Hooking Demo](./assets/HybridAuxIATHooking.gif)

## Author

Koh M. Nakagawa. &copy; FFRI Security, Inc. 2021
