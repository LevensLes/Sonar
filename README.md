

# Sonar Toolkit: A Modern Memory Forensics Tool

Sonar Toolkit is a high-performance memory forensics and analysis application for the Windows operating system. Developed in C++ with the Dear ImGui framework, it provides a suite of tools for security researchers, reverse engineers, and digital forensics professionals to inspect, dump, and analyze the memory of live processes.

Its intuitive graphical interface and multithreaded backend make complex memory analysis tasks faster and more accessible.

## Key Features

*   **Multi-threaded Memory Scanner**
    *   Scan one or more running processes for specific string signatures.
    *   Supports both case-sensitive and case-insensitive scanning.
    *   Powered by a multithreaded scanning engine that utilizes all available CPU cores for maximum speed.
    *   View results in real-time, including the memory addresses of found signatures.

*   **Forensic Toolkit**
    *   **Memory Dumper**: Create complete memory dumps of running processes with multiple output formats.
        *   **Binary Dump**: Generates a raw binary file of a process's committed memory. Includes an "Optimize" mode to skip and de-duplicate identical memory pages (e.g., zero-filled blocks), significantly reducing the size of the final dump file.
        *   **Text (Strings) Dump**: A powerful string extraction tool that dumps all readable strings from a process. It features advanced filtering to refine the output:
            *   Extract ASCII, Unicode, or both string types.
            *   Utilize a custom filter list file to exclude common, irrelevant strings.
            *   Filter non-ASCII characters to produce clean, human-readable text files.
    *   **Differential Analyzer**: Compare two memory dumps (clean vs. dirty snapshots) to identify changes.
        *   **Binary Analysis**: Pinpoints all memory regions that have been modified between two binary dumps.
        *   **Text Analysis**: Isolates and displays only the new strings that have appeared in the "dirty" dump, which is ideal for identifying injected code or malicious activity.
    *   **PE File Inspector**: A static analysis tool for Windows executables.
        *   Supports drag-and-drop for any `.exe` or `.dll` file.
        *   Instantly displays essential PE header information, including architecture (x86/x64), compile timestamp, and a detailed list of all sections with their respective memory permissions (Read/Write/Execute).

*   **Modern and Responsive UI**
    *   Built with the flexible and performant Dear ImGui framework.
    *   Features a clean, custom-themed interface designed for clarity and ease of use.
    *   Includes interactive privilege elevation prompts and clear warnings to guide the user.

## Technical Overview

Sonar Toolkit is a native C++ application that interacts directly with the Windows API to perform low-level analysis.

*   **Process Enumeration**: The application uses `Toolhelp32` snapshot functions to gather a comprehensive list of all running processes.
*   **Memory Access**: It leverages `OpenProcess` with `PROCESS_VM_READ` and other required permissions to access process memory. To gain access to protected system processes, the tool attempts to enable `SeDebugPrivilege`, a critical step that requires administrator rights.
*   **Parallel Processing**: The core scanning and dumping operations are heavily multi-threaded using `std::thread`. The application intelligently divides a target process's memory regions among available CPU cores, allowing them to be processed in parallel. This architecture provides a significant performance boost, especially when analyzing large processes.
*   **Static PE Parsing**: The PE File Inspector reads and parses the file headers (DOS, NT, and Section headers) of an executable to extract its structure and metadata without executing any code.

## Prerequisites for Building

*   A C++17 compatible compiler (e.g., MSVC, Clang, GCC).
*   CMake (version 3.15 or newer).
*   GLFW and its dependencies.

## Building from Source

1.  Clone the repository:
    ```sh
    git clone https://github.com/LevensLes/Sonar.git
    cd sonar
    ```
2.  Create a build directory:
    ```sh
    mkdir build
    cd build
    ```
3.  Run CMake to configure the project and then build it:
    ```sh
    cmake ..
    cmake --build . --config Release
    ```
4.  The executable will be located in the `build/Release` directory.

## Usage Guide

### Important: Running as Administrator

For Sonar Toolkit to access system-level processes and perform its functions correctly, it **must be run with administrator privileges**.

If the application is started with standard user permissions, a notification will appear at the bottom of the window. Click the **Elevate** button to automatically restart Sonar Toolkit with the required administrative rights.

### Quick Scan

1.  Select the **Quick Scan** tab.
2.  Press the **Refresh** button to populate the "Process List".
3.  Select one or more target processes from the list.
4.  In the "Memory Scanner" panel, enter the strings to search for, one per line.
5.  Click **Scan Selected** to begin. Results will appear in the "Results Log" as they are found.

### Memory Dumper

1.  Navigate to the **Forensic Toolkit** tab.
2.  Select a single target process from the list in the "Memory Dumper" panel.
3.  Choose your desired **Dump Type** and configure its options (e.g., Optimize, filter list).
4.  Specify an output path for the dump file.
5.  Click **Create Dump** to start the process.

### Differential Analyzer

1.  Provide the file paths for a "Clean Dump" (the baseline) and a "Dirty Dump" (the snapshot to inspect).
2.  Click **Compare Dumps**. The results will be displayed in the tabs below.

### PE File Inspector

1.  Drag and drop an executable (`.exe`) or library (`.dll`) file onto the application window.
2.  Alternatively, paste the file path into the input field.
3.  Click **Inspect File** to view the PE header information.
