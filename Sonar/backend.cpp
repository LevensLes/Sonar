#define NOMINMAX

#include "backend.h"
#include "ui.h" // Include ui.h to get the definition of AppState
#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <sstream>
#include <fstream>
#include <memory>
#include <vector>
#include <wchar.h>
#include <thread>
#include <mutex>
#include <functional>
#include <algorithm>
#include <string_view>
#include <ctime>
#include <iomanip>
#include <unordered_set>
#include <cwctype>
#include <filesystem>
#include <shlobj.h> // Required for SHGetFolderPathA

// --- HELPER to get a writable application data directory ---
static std::string GetAppDataDirectory() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        std::filesystem::path app_dir = std::filesystem::path(path) / "Sonar";
        std::filesystem::create_directory(app_dir);
        return app_dir.string();
    }
    // Fallback to executable directory if AppData fails for some reason
    char buffer[MAX_PATH];
    GetModuleFileNameA(NULL, buffer, MAX_PATH);
    std::string::size_type pos = std::string(buffer).find_last_of("\\/");
    return std::string(buffer).substr(0, pos);
}


void InitializeAppState(AppState& state) {
    std::string base_dir = GetAppDataDirectory();
    strncpy_s(state.default_output_dir, base_dir.c_str(), sizeof(state.default_output_dir) - 1);

    std::filesystem::path dumps_dir = std::filesystem::path(base_dir) / "dumps";
    std::filesystem::path results_dir = std::filesystem::path(base_dir) / "results";
    std::filesystem::path filters_dir = std::filesystem::path(base_dir) / "filters";
    try {
        std::filesystem::create_directory(dumps_dir);
        std::filesystem::create_directory(results_dir);
        std::filesystem::create_directory(filters_dir);
    }
    catch (const std::filesystem::filesystem_error& e) {}

    // Initialize paths
    strncpy_s(state.dump_output_path, (dumps_dir / "memory_dump.bin").string().c_str(), sizeof(state.dump_output_path) - 1);
    strncpy_s(state.filter_list_path, (filters_dir / "filter.txt").string().c_str(), sizeof(state.filter_list_path) - 1);
    strncpy_s(state.clean_dump_path, (dumps_dir / "clean_dump.txt").string().c_str(), sizeof(state.clean_dump_path) - 1);
    strncpy_s(state.dirty_dump_path, (dumps_dir / "dirty_dump.txt").string().c_str(), sizeof(state.dirty_dump_path) - 1);
    strncpy_s(state.diff_export_path, (results_dir / "diff_report.txt").string().c_str(), sizeof(state.diff_export_path) - 1);

    // Initialize default dumper settings (can be overridden by loaded settings)
    state.dump_type = AppState::DUMP_TYPE_TEXT;
    state.dump_string_type = AppState::DUMP_BOTH;
    state.filter_non_ascii = true;
    state.use_filter_list = false;
    state.dump_optimize = true;

    state.scanner_thread_count = std::thread::hardware_concurrency();
}

static std::string WideStringToString(const WCHAR* wstr) {
    if (wstr == NULL) return "";
    int size_needed =
        WideCharToMultiByte(CP_UTF8, 0, wstr, -1, NULL, 0, NULL, NULL);
    if (size_needed <= 1) return "";
    std::string strTo(size_needed, 0);
    WideCharToMultiByte(CP_UTF8, 0, wstr, -1, &strTo[0], size_needed, NULL, NULL);
    strTo.pop_back();
    return strTo;
}
static std::wstring StringToWString(const std::string& str) {
    if (str.empty()) return std::wstring();
    int size_needed =
        MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), NULL, 0);
    std::wstring wstrTo(size_needed, 0);
    MultiByteToWideChar(CP_UTF8, 0, &str[0], (int)str.size(), &wstrTo[0],
        size_needed);
    return wstrTo;
}
static void GetServicesForPid(DWORD pid, std::string& out_services) {
    SC_HANDLE hSCManager = OpenSCManager(
        NULL, NULL, SC_MANAGER_CONNECT | SC_MANAGER_ENUMERATE_SERVICE);
    if (!hSCManager) {
        hSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ENUMERATE_SERVICE);
        if (!hSCManager) return;
    }
    DWORD bytesNeeded = 0, servicesReturned = 0, resumeHandle = 0;
    if (EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, NULL, 0, &bytesNeeded,
        &servicesReturned, &resumeHandle, NULL)) {
        CloseServiceHandle(hSCManager);
        return;
    }
    if (GetLastError() != ERROR_MORE_DATA || bytesNeeded == 0) {
        CloseServiceHandle(hSCManager);
        return;
    }
    std::vector<BYTE> buffer(bytesNeeded);
    if (!EnumServicesStatusEx(hSCManager, SC_ENUM_PROCESS_INFO, SERVICE_WIN32,
        SERVICE_STATE_ALL, buffer.data(),
        (DWORD)buffer.size(), &bytesNeeded,
        &servicesReturned, &resumeHandle, NULL)) {
        CloseServiceHandle(hSCManager);
        return;
    }
    ENUM_SERVICE_STATUS_PROCESS* pServices =
        reinterpret_cast<ENUM_SERVICE_STATUS_PROCESS*>(buffer.data());
    for (DWORD i = 0; i < servicesReturned; ++i) {
        if (pServices[i].ServiceStatusProcess.dwProcessId == pid) {
            if (!out_services.empty()) out_services += ", ";
            out_services += WideStringToString(pServices[i].lpServiceName);
        }
    }
    CloseServiceHandle(hSCManager);
}

std::vector<ProcessInfo> GetProcessList() {
    std::vector<ProcessInfo> processes;
    const DWORD self_pid = GetCurrentProcessId();
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return processes;
    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);
    if (Process32First(hSnapshot, &pe32)) {
        do {
            if (pe32.th32ProcessID == self_pid) {
                continue;
            }
            ProcessInfo pi;
            pi.pid = pe32.th32ProcessID;
            pi.name = WideStringToString(pe32.szExeFile);
            if (!pi.name.empty()) {
                pi.display_name = pi.name + " (PID: " + std::to_string(pi.pid) + ")";
                if (_stricmp(pi.name.c_str(), "svchost.exe") == 0) {
                    std::string services;
                    GetServicesForPid(pi.pid, services);
                    if (!services.empty()) pi.display_name += " - " + services;
                }
                processes.push_back(pi);
            }
        } while (Process32Next(hSnapshot, &pe32));
    }
    CloseHandle(hSnapshot);
    return processes;
}
PEInfo InspectPEFile(const std::string& file_path) {
    PEInfo result;
    result.file_path = file_path;
    std::ifstream file(file_path, std::ios::binary);
    if (!file.is_open()) {
        result.error = "Error: Could not open file.";
        return result;
    }
    IMAGE_DOS_HEADER dos_header;
    file.read(reinterpret_cast<char*>(&dos_header), sizeof(dos_header));
    if (dos_header.e_magic != IMAGE_DOS_SIGNATURE) {
        result.error = "Error: Not a valid PE file (Invalid DOS signature).";
        return result;
    }
    file.seekg(dos_header.e_lfanew, std::ios::beg);
    IMAGE_NT_HEADERS nt_headers;
    file.read(reinterpret_cast<char*>(&nt_headers), sizeof(nt_headers));
    if (nt_headers.Signature != IMAGE_NT_SIGNATURE) {
        result.error = "Error: Not a valid PE file (Invalid NT signature).";
        return result;
    }
    time_t compile_timestamp = nt_headers.FileHeader.TimeDateStamp;
    tm time_info;
    if (gmtime_s(&time_info, &compile_timestamp) == 0) {
        char time_buf[128];
        strftime(time_buf, sizeof(time_buf), "%Y/%m/%d %H:%M:%S", &time_info);
        result.compile_time = std::string(time_buf);
    }
    else {
        result.compile_time = "Invalid Timestamp";
    }
    switch (nt_headers.FileHeader.Machine) {
    case IMAGE_FILE_MACHINE_I386: result.architecture = "x86 (32-bit)"; break;
    case IMAGE_FILE_MACHINE_AMD64: result.architecture = "x64 (64-bit)"; break;
    case IMAGE_FILE_MACHINE_ARM: result.architecture = "ARM"; break;
    case IMAGE_FILE_MACHINE_ARM64: result.architecture = "ARM64"; break;
    case IMAGE_FILE_MACHINE_IA64: result.architecture = "Intel Itanium"; break;
    default: result.architecture = "Unknown"; break;
    }
    WORD num_sections = nt_headers.FileHeader.NumberOfSections;
    IMAGE_SECTION_HEADER section_header;
    for (int i = 0; i < num_sections; ++i) {
        file.read(reinterpret_cast<char*>(&section_header), sizeof(section_header));
        SectionInfo info;
        info.name = std::string(reinterpret_cast<const char*>(section_header.Name), strnlen(reinterpret_cast<const char*>(section_header.Name), IMAGE_SIZEOF_SHORT_NAME));
        info.virtual_address = section_header.VirtualAddress;
        info.size_of_raw_data = section_header.SizeOfRawData;
        info.characteristics = section_header.Characteristics;
        result.sections.push_back(info);
    }
    file.close();
    return result;
}
static void ReadAllLines(const std::string& path, std::unordered_set<std::string>& lines) { std::ifstream file(path); if (!file.is_open()) return; std::string line; while (std::getline(file, line)) { if (!line.empty() && line.back() == '\r') line.pop_back(); if (!line.empty()) lines.insert(line); } }
static void ExtractStringsFromBuffer(const std::vector<char>& buffer, std::streamsize bytes_read, std::unordered_set<std::string>& string_set) { std::string current_string; for (std::streamsize i = 0; i < bytes_read; ++i) { char c = buffer[i]; if (isprint(static_cast<unsigned char>(c))) { current_string += c; } else { if (current_string.length() >= 4) { string_set.insert(current_string); } current_string.clear(); } } if (current_string.length() >= 4) { string_set.insert(current_string); } }
DiffResult PerformDifferentialAnalysis(const std::string& clean_path, const std::string& dirty_path, std::function<void(float)> progress_callback) { DiffResult result; bool use_text_comparison = (clean_path.size() > 4 && clean_path.substr(clean_path.size() - 4) == ".txt") && (dirty_path.size() > 4 && dirty_path.substr(dirty_path.size() - 4) == ".txt"); if (use_text_comparison) { progress_callback(0.0f); std::unordered_set<std::string> clean_strings; std::unordered_set<std::string> dirty_strings; std::thread clean_thread(ReadAllLines, clean_path, std::ref(clean_strings)); std::thread dirty_thread(ReadAllLines, dirty_path, std::ref(dirty_strings)); clean_thread.join(); dirty_thread.join(); progress_callback(0.5f); for (const auto& str : dirty_strings) { if (clean_strings.find(str) == clean_strings.end()) { result.new_strings.push_back(str); } } std::sort(result.new_strings.begin(), result.new_strings.end()); progress_callback(1.0f); return result; } std::ifstream clean_file(clean_path, std::ios::binary | std::ios::ate); std::ifstream dirty_file(dirty_path, std::ios::binary | std::ios::ate); if (!clean_file.is_open()) { result.error = "Error: Could not open clean dump file."; return result; } if (!dirty_file.is_open()) { result.error = "Error: Could not open dirty dump file."; return result; } std::streampos clean_size = clean_file.tellg(); std::streampos dirty_size = dirty_file.tellg(); clean_file.seekg(0, std::ios::beg); dirty_file.seekg(0, std::ios::beg); if (clean_size == 0 || dirty_size == 0) { result.error = "Error: One or both dump files are empty."; return result; } const size_t CHUNK_SIZE = 4 * 1024 * 1024; std::vector<char> clean_buffer(CHUNK_SIZE); std::vector<char> dirty_buffer(CHUNK_SIZE); std::unordered_set<std::string> clean_strings; std::unordered_set<std::string> dirty_strings; uint64_t current_offset = 0; std::streampos max_size = std::max(clean_size, dirty_size); progress_callback(0.0f); while (current_offset < (uint64_t)max_size) { clean_file.read(clean_buffer.data(), CHUNK_SIZE); dirty_file.read(dirty_buffer.data(), CHUNK_SIZE); std::streamsize clean_bytes_read = clean_file.gcount(); std::streamsize dirty_bytes_read = dirty_file.gcount(); if (clean_bytes_read == 0 && dirty_bytes_read == 0) break; if (clean_bytes_read > 0 || dirty_bytes_read > 0) { size_t clean_hash = (clean_bytes_read > 0) ? std::hash<std::string_view>{}(std::string_view(clean_buffer.data(), clean_bytes_read)) : 0; size_t dirty_hash = (dirty_bytes_read > 0) ? std::hash<std::string_view>{}(std::string_view(dirty_buffer.data(), dirty_bytes_read)) : 0; if (clean_hash != dirty_hash) { result.modified_regions.push_back({ current_offset, (size_t)std::max(clean_bytes_read, dirty_bytes_read), clean_hash, dirty_hash }); } } if (clean_bytes_read > 0) { ExtractStringsFromBuffer(clean_buffer, clean_bytes_read, clean_strings); } if (dirty_bytes_read > 0) { ExtractStringsFromBuffer(dirty_buffer, dirty_bytes_read, dirty_strings); } current_offset += CHUNK_SIZE; progress_callback(static_cast<float>(current_offset) / max_size); } for (const auto& str : dirty_strings) { if (clean_strings.find(str) == clean_strings.end()) { result.new_strings.push_back(str); } } std::sort(result.new_strings.begin(), result.new_strings.end()); progress_callback(1.0f); return result; }
std::pair<bool, std::string> ExportDiffResults(const DiffResult& result, const std::string& output_path) { std::ofstream out_file(output_path); if (!out_file.is_open()) { return { false, "Error: Could not open file for writing: " + output_path }; } auto t = std::time(nullptr); tm tm_info; localtime_s(&tm_info, &t); std::ostringstream time_stream; time_stream << std::put_time(&tm_info, "%Y-%m-%d %H:%M:%S"); out_file << "--- Sonar Differential Analysis Report ---\n"; out_file << "--- Generated on: " << time_stream.str() << " ---\n\n"; if (!result.new_strings.empty()) { out_file << "--- New Strings Found (" << result.new_strings.size() << ") ---\n"; for (const auto& str : result.new_strings) { out_file << str << "\n"; } } else { out_file << "--- No New Strings Found ---\n"; } out_file << "\n\n"; if (!result.modified_regions.empty()) { out_file << "--- Modified Memory Regions (" << result.modified_regions.size() << ") ---\n"; out_file << "Offset,Size (bytes),Clean Hash,Dirty Hash\n"; for (const auto& region : result.modified_regions) { std::stringstream ss; ss << "0x" << std::hex << region.offset << "," << std::dec << region.size << "," << "0x" << std::hex << region.clean_hash << "," << "0x" << region.dirty_hash << "\n"; out_file << ss.str(); } } else { out_file << "--- No Modified Memory Regions Found ---\n"; } out_file.close(); return { true, "Successfully exported results to " + output_path }; }

void PerformQuickScan(AppState& state, const std::vector<ProcessInfo>& targets, const std::string& signatures_str, bool case_insensitive, std::function<void(float, const std::string&)> progress_callback) {

    struct Signature { std::string original; std::string ascii_to_find; std::wstring wide_to_find; };
    std::vector<Signature> signatures;
    size_t max_sig_len = 0;
    std::stringstream ss(signatures_str);
    std::string line;
    while (std::getline(ss, line)) {
        if (!line.empty() && line.back() == '\r') line.pop_back();
        if (line.empty()) continue;
        max_sig_len = std::max(max_sig_len, line.length());
        if (case_insensitive) {
            std::string lower_line = line;
            std::transform(lower_line.begin(), lower_line.end(), lower_line.begin(), [](unsigned char c) { return std::tolower(c); });
            signatures.push_back({ line, lower_line, StringToWString(lower_line) });
        }
        else {
            signatures.push_back({ line, line, StringToWString(line) });
        }
    }
    if (signatures.empty() || targets.empty()) {
        progress_callback(1.0f, "No targets or signatures.");
        state.scan_running = false;
        return;
    }

    progress_callback(0.0f, "Enumerating memory regions...");
    struct ScanTask {
        ProcessInfo target;
        MEMORY_BASIC_INFORMATION region;
    };
    std::vector<ScanTask> all_regions;
    size_t processes_failed_to_open = 0;

    for (const auto& target : targets) {
        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, target.pid);
        if (hProcess == NULL) {
            ScanResult error_res;
            error_res.pid = target.pid;
            error_res.process_name = target.name;
            error_res.address = 0;
            error_res.signature = (GetLastError() == ERROR_ACCESS_DENIED) ? "[ACCESS_DENIED]" : "[ERROR: Could not open process]";
            {
                std::lock_guard<std::mutex> lock(state.scan_result_queue_mutex);
                state.scan_result_queue.push_back(error_res);
            }
            processes_failed_to_open++;
            continue;
        }

        unsigned char* address = 0;
        MEMORY_BASIC_INFORMATION mbi;
        while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
            if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) {
                all_regions.push_back({ target, mbi });
            }
            address += mbi.RegionSize;
        }
        CloseHandle(hProcess);
    }

    if (all_regions.empty()) {
        progress_callback(1.0f, processes_failed_to_open > 0 ? "No accessible memory regions found." : "Scan complete. No memory to scan.");
        state.scan_running = false;
        return;
    }

    std::atomic<size_t> regions_scanned = 0;
    const size_t total_regions = all_regions.size();
    const int num_threads = state.scanner_thread_count;
    std::vector<std::thread> threads;

    for (int t = 0; t < num_threads; ++t) {
        threads.emplace_back([&, t]() {
            const SIZE_T CHUNK_SIZE = 4 * 1024 * 1024;
            const SIZE_T OVERLAP = (max_sig_len > 0) ? (max_sig_len * sizeof(wchar_t) - 1) : 0;
            std::vector<char> buffer(CHUNK_SIZE + OVERLAP);

            HANDLE hProcess = NULL;
            DWORD current_pid = 0;

            for (size_t i = t; i < total_regions; i += num_threads) {
                const auto& task = all_regions[i];

                if (task.target.pid != current_pid) {
                    if (hProcess) CloseHandle(hProcess);
                    hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, task.target.pid);
                    current_pid = task.target.pid;
                }
                if (hProcess == NULL) {
                    regions_scanned++;
                    continue;
                }

                char* current_base = (char*)task.region.BaseAddress;
                SIZE_T total_region_size = task.region.RegionSize;
                SIZE_T total_bytes_scanned = 0;
                while (total_bytes_scanned < total_region_size) {
                    SIZE_T bytes_to_read = std::min(CHUNK_SIZE, total_region_size - total_bytes_scanned);
                    SIZE_T bytes_read = 0;
                    if (ReadProcessMemory(hProcess, current_base + total_bytes_scanned, buffer.data(), bytes_to_read, &bytes_read) && bytes_read > 0) {
                        std::string_view haystack_ascii(buffer.data(), bytes_read);
                        std::wstring_view haystack_wide((const wchar_t*)buffer.data(), bytes_read / sizeof(wchar_t));

                        std::vector<ScanResult> local_results;
                        for (const auto& sig : signatures) {
                            for (size_t pos = 0; (pos = haystack_ascii.find(sig.ascii_to_find, pos)) != std::string_view::npos; ++pos) {
                                local_results.push_back({ sig.original + " (ASCII)", task.target.name, task.target.pid, (void*)(current_base + total_bytes_scanned + pos) });
                            }
                            for (size_t pos = 0; (pos = haystack_wide.find(sig.wide_to_find, pos)) != std::wstring_view::npos; ++pos) {
                                local_results.push_back({ sig.original + " (Unicode)", task.target.name, task.target.pid, (void*)(current_base + total_bytes_scanned + (pos * sizeof(wchar_t))) });
                            }
                        }

                        if (!local_results.empty()) {
                            std::lock_guard<std::mutex> lock(state.scan_result_queue_mutex);
                            state.scan_result_queue.insert(state.scan_result_queue.end(), local_results.begin(), local_results.end());
                        }
                        total_bytes_scanned += bytes_read;
                    }
                    else {
                        break;
                    }
                }

                size_t scanned_count = regions_scanned.fetch_add(1) + 1;
                float progress = static_cast<float>(scanned_count) / total_regions;
                char msg[256];
                snprintf(msg, sizeof(msg), "Scanning region %zu/%zu in %s...", scanned_count, total_regions, task.target.name.c_str());
                progress_callback(progress, msg);
            }
            if (hProcess) CloseHandle(hProcess);
            });
    }

    for (auto& th : threads) {
        th.join();
    }

    progress_callback(1.0f, "Scan complete.");
    state.scan_running = false;
}
std::pair<bool, std::string> CreateManualMemoryDump(DWORD processId, const std::string& output_path, bool optimize_dump, bool as_text, int dump_string_type, const std::string& filter_list_path, bool use_filter_list, bool filter_non_ascii, std::function<void(float, const std::string&)> progress_callback) {
    HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, processId);
    if (hProcess == NULL) {
        if (GetLastError() == ERROR_ACCESS_DENIED) { return { false, "[ACCESS_DENIED]" }; }
        return { false, "ERROR: OpenProcess failed. Error code: " + std::to_string(GetLastError()) };
    }
    progress_callback(0.0f, "Enumerating memory regions...");
    std::vector<MEMORY_BASIC_INFORMATION> regions_to_dump;
    unsigned char* address = 0;
    MEMORY_BASIC_INFORMATION mbi;
    while (VirtualQueryEx(hProcess, address, &mbi, sizeof(mbi))) {
        if (mbi.State == MEM_COMMIT && !(mbi.Protect & (PAGE_NOACCESS | PAGE_GUARD))) { regions_to_dump.push_back(mbi); }
        address += mbi.RegionSize;
    }
    if (regions_to_dump.empty()) { CloseHandle(hProcess); return { false, "ERROR: Could not find any commit-able memory regions in the process." }; }
    const int num_threads = std::thread::hardware_concurrency();
    std::vector<std::thread> threads;
    std::atomic<size_t> total_bytes_written = 0;
    std::atomic<size_t> total_bytes_scanned_val = 0;
    if (as_text) {
        std::unordered_set<std::string> filters;
        if (use_filter_list) {
            std::ifstream filter_file(filter_list_path);
            if (filter_file.is_open()) {
                std::string line;
                while (std::getline(filter_file, line)) {
                    if (!line.empty()) {
                        std::transform(line.begin(), line.end(), line.begin(), [](unsigned char c) { return std::tolower(c); });
                        filters.insert(line);
                    }
                }
            }
        }
        std::vector<std::unordered_set<std::string>> thread_local_sets(num_threads);
        std::atomic<size_t> regions_processed = 0;
        const size_t total_regions = regions_to_dump.size();
        const int progress_update_interval = std::max(1, (int)total_regions / 100);
        bool do_ascii_pass = (dump_string_type == 0 || dump_string_type == 2);
        bool do_unicode_pass = (dump_string_type == 1 || dump_string_type == 2);
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&, t]() {
                const size_t BUFFER_SIZE = 65536;
                std::vector<char> buffer(BUFFER_SIZE);
                for (size_t i = t; i < regions_to_dump.size(); i += num_threads) {
                    const auto& region = regions_to_dump[i];
                    char* base = (char*)region.BaseAddress;
                    char* end = base + region.RegionSize;
                    char* current = base;
                    while (current < end) {
                        SIZE_T bytes_to_read = std::min(BUFFER_SIZE, (SIZE_T)(end - current));
                        SIZE_T bytes_read = 0;
                        if (!ReadProcessMemory(hProcess, current, buffer.data(), bytes_to_read, &bytes_read) || bytes_read == 0) { break; }
                        if (do_ascii_pass) {
                            const char* buf_ptr = buffer.data();
                            const char* buf_end = buf_ptr + bytes_read;
                            while (buf_ptr < buf_end) {
                                if (isprint(static_cast<unsigned char>(*buf_ptr))) {
                                    const char* start = buf_ptr;
                                    while (buf_ptr < buf_end && isprint(static_cast<unsigned char>(*buf_ptr))) { buf_ptr++; }
                                    if (buf_ptr - start >= 4) { thread_local_sets[t].insert(std::string(start, buf_ptr - start)); }
                                }
                                else { buf_ptr++; }
                            }
                        }
                        if (do_unicode_pass) {
                            const wchar_t* wbuf_ptr = reinterpret_cast<const wchar_t*>(buffer.data());
                            const wchar_t* wbuf_end = wbuf_ptr + (bytes_read / sizeof(wchar_t));
                            while (wbuf_ptr < wbuf_end) {
                                if (iswprint(*wbuf_ptr)) {
                                    const wchar_t* start = wbuf_ptr;
                                    while (wbuf_ptr < wbuf_end && iswprint(*wbuf_ptr)) { wbuf_ptr++; }
                                    if (wbuf_ptr - start >= 4) {
                                        std::wstring wide_str(start, wbuf_ptr - start);
                                        bool is_valid = true;
                                        if (filter_non_ascii) {
                                            for (wchar_t wc : wide_str) { if (wc < 0 || wc > 127) { is_valid = false; break; } }
                                        }
                                        if (is_valid) { thread_local_sets[t].insert(WideStringToString(wide_str.c_str())); }
                                    }
                                }
                                else { wbuf_ptr++; }
                            }
                        }
                        current += bytes_read;
                    }
                    size_t processed = regions_processed.fetch_add(1) + 1;
                    if (processed % progress_update_interval == 0) {
                        char msg[128]; snprintf(msg, sizeof(msg), "Scanning... %zu / %zu regions", processed, total_regions);
                        progress_callback(static_cast<float>(processed) / total_regions, msg);
                    }
                }
                });
        }
        for (auto& th : threads) th.join();
        progress_callback(0.95f, "Merging and filtering results...");
        std::unordered_set<std::string> final_strings;
        for (const auto& local_set : thread_local_sets) { final_strings.insert(local_set.begin(), local_set.end()); }
        if (use_filter_list && !filters.empty()) {
            std::vector<std::string> strings_to_remove;
            for (const auto& found_str : final_strings) {
                std::string lower_found_str = found_str;
                std::transform(lower_found_str.begin(), lower_found_str.end(), lower_found_str.begin(), [](unsigned char c) { return std::tolower(c); });
                for (const auto& filter_str : filters) {
                    if (lower_found_str.find(filter_str) != std::string::npos) {
                        strings_to_remove.push_back(found_str);
                        break;
                    }
                }
            }
            for (const auto& str_to_remove : strings_to_remove) { final_strings.erase(str_to_remove); }
        }
        progress_callback(0.99f, "Writing unique strings to file...");
        std::ofstream out_file(output_path, std::ios::out);
        if (!out_file.is_open()) { CloseHandle(hProcess); return { false, "ERROR: Failed to create final output file." }; }
        for (const auto& s : final_strings) { out_file << s << '\n'; }
        total_bytes_written = out_file.tellp();
        out_file.close();
    }
    else {
        std::ofstream out_file(output_path, std::ios::out | std::ios::binary);
        if (!out_file.is_open()) { CloseHandle(hProcess); return { false, "ERROR: Failed to create output file: " + output_path }; }
        std::mutex file_mutex;
        std::unordered_set<size_t> written_hashes;
        for (int t = 0; t < num_threads; ++t) {
            threads.emplace_back([&, t]() {
                const size_t CHUNK_SIZE = 65536;
                std::vector<char> buffer(CHUNK_SIZE);
                for (size_t i = t; i < regions_to_dump.size(); i += num_threads) {
                    const auto& region = regions_to_dump[i];
                    char* current = (char*)region.BaseAddress;
                    char* end = current + region.RegionSize;
                    while (current < end) {
                        SIZE_T bytes_to_read = std::min(CHUNK_SIZE, (size_t)(end - current));
                        SIZE_T bytes_read = 0;
                        if (ReadProcessMemory(hProcess, current, buffer.data(), bytes_to_read, &bytes_read) && bytes_read > 0) {
                            total_bytes_scanned_val += bytes_read;
                            bool should_write = true;
                            if (optimize_dump) {
                                size_t page_hash = std::hash<std::string_view>{}(std::string_view(buffer.data(), bytes_read));
                                std::lock_guard<std::mutex> lock(file_mutex);
                                if (written_hashes.find(page_hash) != written_hashes.end()) { should_write = false; }
                                else { written_hashes.insert(page_hash); }
                            }
                            if (should_write) {
                                std::lock_guard<std::mutex> lock(file_mutex);
                                out_file.write(buffer.data(), bytes_read);
                                total_bytes_written += bytes_read;
                            }
                            current += bytes_read;
                        }
                        else { break; }
                    }
                }
                });
        }
        for (auto& th : threads) th.join();
        out_file.close();
    }
    CloseHandle(hProcess);
    char final_log[256];
    if (as_text) { snprintf(final_log, sizeof(final_log), "SUCCESS: Text dump complete. Wrote %.2f MB of unique, filtered strings.", total_bytes_written / (1024.0 * 1024.0)); }
    else if (optimize_dump) { snprintf(final_log, sizeof(final_log), "SUCCESS: Optimized dump complete. Wrote %.2f MB (from %.2f MB).", total_bytes_written / (1024.0 * 1024.0), total_bytes_scanned_val / (1024.0 * 1024.0)); }
    else { snprintf(final_log, sizeof(final_log), "SUCCESS: Dump complete. Wrote %.2f MB.", total_bytes_written / (1024.0 * 1024.0)); }
    progress_callback(1.0f, "Done!");
    return { true, std::string(final_log) };
}