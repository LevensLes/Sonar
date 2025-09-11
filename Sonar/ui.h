#pragma once

#include "imgui.h"
#include "backend.h"
#include "icons.h"
#include <string>
#include <vector>
#include <mutex>
#include <chrono>
#include <GLFW/glfw3.h>


// Struct for colored log lines (UI-specific)
struct ColoredLine {
    ImVec4 color;
    std::string text;
};

// The main application state, now focused on UI
struct AppState {
    enum DumpStringType { DUMP_ASCII_ONLY = 0, DUMP_UNICODE_ONLY = 1, DUMP_BOTH = 2 };
    enum Panel { PANEL_QUICK_SCAN = 0, PANEL_FORENSIC = 1, PANEL_SETTINGS = 2 };
    enum DumpType { DUMP_TYPE_BINARY = 0, DUMP_TYPE_TEXT = 1 };

    // --- Settings ---
    // Appearance
    ImVec4 accent_color = ImVec4(0.780f, 0.573f, 0.918f, 1.00f);
    bool settings_enable_animations = false;

    // Performance
    int scanner_thread_count; // Will be initialized by the backend

    // Workflow
    bool scan_case_insensitive = true;
    bool clear_signatures_on_complete = false;
    char default_output_dir[512];
    // Note: Dumper settings are also part of workflow, but are modified on the Forensic page.
    // Their default values will be loaded from settings.


    // --- UI State ---
    Panel active_panel = PANEL_QUICK_SCAN;

    // Quick Scan
    std::vector<bool> quick_scan_selections;
    int last_quick_scan_selection = -1;
    char signature_buffer[8192] = "Enter strings here, one per line...";
    std::vector<ColoredLine> quick_scan_lines;
    std::vector<ProcessInfo> process_list;
    char process_filter[128] = "";
    float scan_progress = 0.0f;
    std::string scan_status;
    bool show_scan_all_warning = false;

    // Forensic Panel (Shared State)
    std::vector<ColoredLine> forensic_log_lines;

    // Forensic - Dumper
    int forensic_dump_selection = -1;
    char dump_output_path[512];
    bool dump_running = false;
    char forensic_process_filter[128] = "";
    bool dump_optimize = true;
    DumpType dump_type;
    float dump_progress = 0.0f;
    std::string dump_status;
    DumpStringType dump_string_type;
    char filter_list_path[512];
    bool use_filter_list;
    bool filter_non_ascii;

    // Forensic - PE Inspector
    char file_to_inspect[512] = "";
    PEInfo pe_info;

    // Forensic - Differential Analyzer
    char clean_dump_path[512];
    char dirty_dump_path[512];
    bool diff_running = false;
    DiffResult diff_result;
    bool new_diff_results_ready = false;
    float diff_progress = 0.0f;
    char diff_export_path[512];

    // Shared UI
    bool scan_running = false;
    bool has_debug_privilege = false;

    // Elevation Flow
    bool elevation_requested = false;
    bool show_elevation_modal = false;
    bool toast_dismissed = false;
    bool show_admin_toast = false;
    bool user_acknowledged_limited_scan = false;


    // --- Threading Internals ---
    std::vector<ScanResult> scan_result_queue;
    std::mutex scan_result_queue_mutex;
    std::mutex log_mutex;
    std::mutex scan_progress_mutex;
    std::mutex dump_progress_mutex;
    std::mutex diff_progress_mutex;
    std::string path_to_drop;
    std::mutex drop_mutex;
};

// Config Functions
void SaveSettings(const AppState& state);
void LoadSettings(AppState& state);


// UI Function Declarations
void ApplySonarStyle(AppState& state);
void RenderUI(AppState& state, GLFWwindow* window);
void PushLog(std::vector<ColoredLine>& list, const ImVec4& color, const char* fmt, ...);