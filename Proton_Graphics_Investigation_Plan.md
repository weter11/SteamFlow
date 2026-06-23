# Root-Cause Investigation Plan: Proton Graphics Initialization Failure

This document outlines a systematic approach to diagnosing the `nodrv_CreateWindow` error when running Proton builds as standalone Wine outside of Steam.

## 1. Deep Technical Analysis: Driver Loading in Wine

### 1.1 Discovery & Selection Sequence
1.  **Registry Check**: Wine checks `HKEY_CURRENT_USER\Software\Wine\Drivers`.
    - Key: `Graphics` (String)
    - Value: `x11` (default), `wayland`, or `mac`.
2.  **Internal Default**: If no registry key exists, Wine uses a hardcoded fallback list based on the platform (e.g., `x11`).
3.  **Path Resolution**:
    - The driver name `x11` is translated to `winex11.drv`.
    - Wine searches `WINEDLLPATH` for the PE file `winex11.drv`.
    - The PE loader identifies the corresponding Unix shared library: `winex11.drv.so`.
4.  **Dynamic Loading**:
    - Wine calls `dlopen()` on `winex11.drv.so`.
    - The driver's `DriverInit` or `wine_display_driver_init` function is called.
5.  **Failure State**:
    - If `dlopen()` fails or the initialization function returns an error (e.g., can't connect to X11), Wine falls back to the `null` driver.
    - Subsequent attempts to create a window trigger `nodrv_CreateWindow`.

### 1.2 Search Paths for `winex11.drv.so`
-   **WINEDLLPATH**: The primary search path for Wine's internal DLLs.
-   **Internal lib directory**: Usually `<proton_root>/lib64/wine` and `<proton_root>/lib/wine`.
-   **Architecture Specifics**: Modern Wine (Proton 8+) uses architecture-specific subdirectories: `x86_64-windows/` for the PE file and the `.so` is typically sibling to it or in a `lib64/` path.

---

## 2. Conditions for `nodrv_CreateWindow` (Even when file exists)

1.  **Missing Library Dependencies**: `winex11.drv.so` links to `libX11`, `libXext`, `libxcb`, etc. If these aren't found in `LD_LIBRARY_PATH` or `/lib64`, loading fails.
2.  **Symbol/Version Mismatch**: Proton is built against the Steam Runtime (e.g., Soldier/Sniper). If the host has older libraries or incompatible symbol versions, `dlopen` will fail with "symbol lookup error".
3.  **DISPLAY Environment Variable**: If `DISPLAY` is not set or refers to an invalid socket, the driver's initialization function (after successful `dlopen`) will fail to connect to the X server.
4.  **Architecture Mismatch**: Attempting to load a 64-bit `winex11.drv.so` into a 32-bit `wine` process (or vice versa).
5.  **Steam Runtime Assumptions**: Proton drivers may expect specific libraries provided by `pressure-vessel` (like `libvulkan.so.1` or specific GL implementations) which are absent in standalone execution.

---

## 3. Tracing & Diagnostic Commands

### 3.1 Wine-level Tracing
```bash
# Trace DLL/Module loading and driver initialization
# Note: 'x11drv' is the correct debug channel for the X11 graphics driver
WINEDEBUG=+loaddll,+module,+x11drv wine your_app.exe
```
*   **What to look for**: Check if `winex11.drv` is even attempted. Look for `dlopen` failures or "failed to load" errors in the log.

### 3.2 Dynamic Linker Tracing
```bash
# Show every library the linker attempts to load and where it looks
LD_DEBUG=libs,files wine your_app.exe 2> ld_debug.log
```
*   **What to look for**: Locate the `dlopen` call for `winex11.drv.so`. The linker will explicitly state which dependency (e.g., `libX11.so.6`) it is searching for and exactly where it is failing (e.g., `cannot open shared object file`).

### 3.3 Static Dependency & Symbol Analysis
```bash
# 1. Check for missing shared libraries recursively
ldd -r /path/to/proton/lib64/wine/x86_64-unix/winex11.drv.so

# 2. Inspect RPATH/RUNPATH (critical for Proton standalone)
# Proton drivers often have RPATH pointing to non-existent Steam Runtime paths
readelf -d /path/to/proton/lib64/wine/x86_64-unix/winex11.drv.so | grep -E "RPATH|RUNPATH"

# 3. Verify symbol versions and required libraries
# Useful for detecting GLIBC or X11 version mismatches
objdump -p /path/to/proton/lib64/wine/x86_64-unix/winex11.drv.so | grep -A 10 "Version References:"
```
*   **What to look for**: "not found" in `ldd`, RPATHs that don't match your host's library locations, or symbol versions (e.g., `GLIBC_2.34`) higher than what your host provides.

### 3.4 System Call Tracing
```bash
# Trace file access and X11 connection attempts
strace -f -e trace=openat,access,connect wine your_app.exe
```
*   **What to look for**: Search for `/tmp/.X11-unix/X0` access. Check if it's "Connection refused" (driver loaded but X server rejected it) vs "No such file or directory" (driver looking in the wrong place).

---

## 4. Proton vs wine-tkg: The "Standalone Gap"

| Feature | wine-tkg | Proton |
| :--- | :--- | :--- |
| **Build Target** | Host environment / Generic Distro | Steam Runtime (Ubuntu-based) |
| **Dependencies** | Linked to host system libs | Linked to bundled/runtime libs |
| **Isolation** | None (uses host namespaces) | `pressure-vessel` (containerized) |
| **Entry Point** | `wine` binary directly | `proton` Python script wrapper |

**Proton's Standalone Killers:**
-   **RPATH**: Proton binaries often have `RPATH` pointing to Steam Runtime paths that don't exist on your host.
-   **Steam Runtime**: The `proton` script sets up a massive `LD_LIBRARY_PATH` and often launches the game inside a container (Sniper/Soldier). Standalone execution loses this entire support layer.

---

## 5. Prioritized Hypotheses

### Hypothesis 1: Missing Steam Runtime Libraries (Most Probable)
*   **Reason**: Proton drivers link to specific versions of X11/GL libs provided by the Steam Runtime.
*   **Evidence**: `ldd` shows "not found" for libs like `libX11.so.6`.
*   **Verify**: Run `ldd` on `winex11.drv.so`.
*   **Falsify**: If `ldd` shows all libs resolved to host paths, this is not the cause.

### Hypothesis 2: LD_LIBRARY_PATH / WINEDLLPATH configuration gap
*   **Reason**: Standalone Wine doesn't know where Proton keeps its drivers.
*   **Evidence**: `WINEDEBUG=+module` shows it can't find `winex11.drv`.
*   **Verify**: Explicitly set `WINEDLLPATH` to the Proton lib directories.
*   **Falsify**: If setting the path still results in `nodrv_CreateWindow` despite finding the file.

### Hypothesis 3: X11 Socket / Permission Issue
*   **Reason**: Proton may be trying to use a different X11 socket or failing due to sandbox-like expectations.
*   **Evidence**: `strace` shows failed `connect()` to `/tmp/.X11-unix/X0`.
*   **Verify**: Check `echo $DISPLAY` and `xhost +` (for testing).
*   **Falsify**: If other X11 apps (including `wine-tkg`) work under the same environment.
