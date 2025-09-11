# Sonar Toolkit: A Modern Memory Forensics Tool

Sonar Toolkit is a powerful and intuitive memory forensics and analysis application for Windows, built with C++ and the Dear ImGui graphical framework. It provides a suite of tools designed for security researchers, reverse engineers, and digital forensics enthusiasts to inspect, dump, and analyze the memory of live processes.

Its user-friendly interface and multithreaded backend make complex memory analysis tasks faster and more accessible.

*(Suggestion: Place a screenshot of the main application window here!)*
`[Screenshot of Sonar Toolkit in action]`

##  Key Features

*   **Quick Scan (Multi-threaded Memory Scanner)**
    *   Scan running processes for specific strings (ASCII and Unicode).
    *   Supports case-insensitive scanning.
    *   Blazing fast results powered by a multithreaded scanning engine.
    *   Live results log that shows memory addresses of found signatures.

*   **Forensic Toolkit**
    *   **Memory Dumper**: Create full memory dumps of running processes.
        *   **Binary Dump**: Creates a raw binary dump of a process's memory. Features an "Optimize" mode to skip identical memory pages (like zeroed-out blocks), significantly reducing dump size.
        *   **Text (Strings) Dump**: A powerful string extraction tool that dumps all readable strings from a process. Includes advanced filtering options to find exactly what you need:
            *   Filter by string type (ASCII, Unicode, or Both).
            *   Exclude common noise with a custom filter list file.
            *   Filter out non-standard characters to produce clean, readable output.
    *   **Differential Analyzer**: Compare two memory dumps to identify changes.
        *   **Binary Dumps**: Identifies all memory regions that have been modified between a "clean" and "dirty" snapshot.
        *   **Text Dumps**: Pinpoints all new strings that have appeared in the "dirty" dump, perfect for isolating malicious activity or finding injected code.
    *   **PE File Inspector**: A static analysis tool for executables.
        *   Drag and drop any `.exe` or `.dll` file.
        *   Instantly view key information like architecture (x86/x64), compile time, and a list of all sections with their memory permissions (Read/Write/Execute).

*   **Modern & Responsive UI**
    *   Built with the flexible Dear ImGui framework.
    *   Features a custom-themed interface for a clean and professional look.
    *   Interactive privilege elevation prompts to guide the user.

##  How It Works

Sonar Toolkit is a native C++ application that interacts directly with the Windows API to perform its analysis.

*   **Process Enumeration**: It uses the `Toolhelp32` snapshot functions to gather a list of all running processes and their associated services.
*   **Memory Access**: To read process memory, it leverages `OpenProcess` with `PROCESS_VM_READ` permissions. For full access to protected system processes, it attempts to enable `SeDebugPrivilege`, which requires the application to be run as an Administrator.
*   **Scanning & Dumping**: The core memory operations are heavily multi-threaded using `std::thread`. The application divides a process's memory regions among all available CPU cores, allowing them to be scanned or dumped in parallel. This results in a significant performance boost, especially for large processes.
*   **PE Parsing**: The PE Inspector reads the file headers (DOS, NT, and Section headers) of an executable to parse its structure and metadata without actually running the file.

##  How to Use

### Important: Running as Administrator

For Sonar Toolkit to function properly and access all system processes, it **must be run with administrator privileges**.

If you run the program normally, an interactive notification will appear at the bottom of the window. You can click the **"Elevate"** button to automatically restart the application with the required permissions.

### Quick Scan

1.  Click the **Refresh** button on the "Process List" card to get a current list of processes.
2.  Select the target process you wish to scan from the list.
3.  In the "Memory Scanner" card, type the strings you want to search for, with each string on a new line.
4.  Click the **Scan Process** button.
5.  Results will appear in real-time in the "Results Log".

### Memory Dumper

1.  Navigate to the "Forensic Toolkit" tab.
2.  Select the target process from the list in the "Memory Dumper" card.
3.  Choose your **Dump Type**:
    *   **Binary**: For a raw memory dump. Check **Optimize** to reduce file size.
    *   **Text (Strings)**: To extract only readable strings. Configure the additional filtering options as needed.
4.  Set the output path for the dump file.
5.  Click the **Create Dump** button. The progress bar will show the status.

### Differential Analyzer

1.  Provide the file paths for a "Clean Dump" (your baseline) and a "Dirty Dump" (the one you want to inspect for changes). These can be either binary or text dumps.
2.  Click the **Compare Dumps** button.
3.  The results will be displayed in the tabs below, showing either new strings or modified memory regions.

### PE File Inspector

1.  Simply drag and drop an executable (`.exe`) or library (`.dll`) file directly onto the Sonar Toolkit window.
2.  Alternatively, you can paste the file path into the input box.
3.  Click the **Inspect File** button to view the PE header information.
