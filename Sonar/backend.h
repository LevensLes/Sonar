#pragma once

#include <string>
#include <vector>
#include <windows.h>
#include <utility>
#include <functional>

// Forward-declare AppState to avoid circular dependency
struct AppState;

// Struct to hold a single scan result
struct ScanResult {
    std::string signature;
    std::string process_name;
    DWORD pid;
    void* address;
};

// Struct to hold real process information
struct ProcessInfo {
    DWORD pid;
    std::string name;
    std::string display_name;
};

// Structs for the PE File Inspector
struct SectionInfo {
    std::string name;
    DWORD virtual_address;
    DWORD size_of_raw_data;
    DWORD characteristics;
};

struct PEInfo {
    std::string file_path;
    std::string compile_time;
    std::string architecture;
    std::vector<SectionInfo> sections;
    std::string error;
};

// Structs for the Differential Analyzer
struct ModifiedRegion {
    uint64_t offset;
    size_t size;
    size_t clean_hash;
    size_t dirty_hash;
};

struct DiffResult {
    std::vector<std::string> new_strings;
    std::vector<ModifiedRegion> modified_regions;
    std::string error;
};

// --- Function Declarations ---
void InitializeAppState(AppState& state);
std::vector<ProcessInfo> GetProcessList();
void PerformQuickScan(AppState& state, const std::vector<ProcessInfo>& targets, const std::string& signatures_str, bool case_insensitive, std::function<void(float, const std::string&)> progress_callback);
PEInfo InspectPEFile(const std::string& file_path);
DiffResult PerformDifferentialAnalysis(const std::string& clean_path, const std::string& dirty_path, std::function<void(float)> progress_callback);
std::pair<bool, std::string> ExportDiffResults(const DiffResult& result, const std::string& output_path);

std::pair<bool, std::string> CreateManualMemoryDump(
    DWORD processId,
    const std::string& output_path,
    bool optimize_dump,
    bool as_text,
    int dump_string_type,
    const std::string& filter_list_path,
    bool use_filter_list,
    bool filter_non_ascii,
    std::function<void(float, const std::string&)> progress_callback
);