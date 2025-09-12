
#define NOMINMAX
#include <GLFW/glfw3.h>
#include "ui.h"
#include "imgui_internal.h"
#include <cstdio>
#include <thread>
#include <mutex>
#include <shellapi.h>
#include <string>
#include <sstream>
#include <iomanip>
#include <fstream>
#include <windows.h>
#include <shlobj.h>
#include <iostream>
#include <filesystem>
#include <algorithm> 


// --- HELPER to get a writable application data directory ---
static std::string GetAppDataDirectory() {
    char path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathA(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        std::filesystem::path app_dir = std::filesystem::path(path) / "Sonar";
        std::filesystem::create_directory(app_dir);
        return app_dir.string();
    }
    // Fallback in case AppData fails
    return ".";
}

// --- SETTINGS PERSISTENCE ---

std::string GetConfigFilePath() {
    return GetAppDataDirectory() + "\\sonar_settings.ini";
}

void SaveSettings(const AppState& state) {
    std::ofstream settings_file(GetConfigFilePath());
    if (!settings_file.is_open()) return;

    settings_file << "[Appearance]" << std::endl;
    settings_file << "accent_color_r=" << state.accent_color.x << std::endl;
    settings_file << "accent_color_g=" << state.accent_color.y << std::endl;
    settings_file << "accent_color_b=" << state.accent_color.z << std::endl;
    settings_file << "enable_animations=" << state.settings_enable_animations << std::endl;

    settings_file << "\n[Performance]" << std::endl;
    settings_file << "scanner_thread_count=" << state.scanner_thread_count << std::endl;

    settings_file << "\n[Workflow]" << std::endl;
    settings_file << "case_insensitive=" << state.scan_case_insensitive << std::endl;
    settings_file << "clear_signatures_on_complete=" << state.clear_signatures_on_complete << std::endl;
    settings_file << "default_output_dir=" << state.default_output_dir << std::endl;
    settings_file << "dump_output_path=" << state.dump_output_path << std::endl;
    settings_file << "filter_list_path=" << state.filter_list_path << std::endl;
    settings_file << "clean_dump_path=" << state.clean_dump_path << std::endl;
    settings_file << "dirty_dump_path=" << state.dirty_dump_path << std::endl;
    settings_file << "diff_export_path=" << state.diff_export_path << std::endl;
    settings_file << "file_to_inspect=" << state.file_to_inspect << std::endl;

    settings_file << "\n[DumperDefaults]" << std::endl;
    settings_file << "dump_type=" << state.dump_type << std::endl;
    settings_file << "dump_optimize=" << state.dump_optimize << std::endl;
    settings_file << "dump_string_type=" << state.dump_string_type << std::endl;
    settings_file << "use_filter_list=" << state.use_filter_list << std::endl;
    settings_file << "filter_non_ascii=" << state.filter_non_ascii << std::endl;
}


void LoadSettings(AppState& state) {
    std::ifstream settings_file(GetConfigFilePath());
    if (!settings_file.is_open()) return;

    std::string line;
    while (std::getline(settings_file, line)) {
        if (line.empty() || line[0] == '[' || line[0] == '#') continue;

        std::istringstream iss(line);
        std::string key, value;
        if (std::getline(iss, key, '=') && std::getline(iss, value)) {
            try {
                // Appearance
                if (key == "accent_color_r") state.accent_color.x = std::stof(value);
                else if (key == "accent_color_g") state.accent_color.y = std::stof(value);
                else if (key == "accent_color_b") state.accent_color.z = std::stof(value);
                else if (key == "enable_animations") state.settings_enable_animations = (std::stoi(value) != 0);
                // Performance
                else if (key == "scanner_thread_count") state.scanner_thread_count = std::stoi(value);
                // Workflow
                else if (key == "case_insensitive") state.scan_case_insensitive = (std::stoi(value) != 0);
                else if (key == "clear_signatures_on_complete") state.clear_signatures_on_complete = (std::stoi(value) != 0);
                else if (key == "default_output_dir") strncpy_s(state.default_output_dir, value.c_str(), sizeof(state.default_output_dir) - 1);
                else if (key == "dump_output_path") strncpy_s(state.dump_output_path, value.c_str(), sizeof(state.dump_output_path) - 1);
                else if (key == "filter_list_path") strncpy_s(state.filter_list_path, value.c_str(), sizeof(state.filter_list_path) - 1);
                else if (key == "clean_dump_path") strncpy_s(state.clean_dump_path, value.c_str(), sizeof(state.clean_dump_path) - 1);
                else if (key == "dirty_dump_path") strncpy_s(state.dirty_dump_path, value.c_str(), sizeof(state.dirty_dump_path) - 1);
                else if (key == "diff_export_path") strncpy_s(state.diff_export_path, value.c_str(), sizeof(state.diff_export_path) - 1);
                else if (key == "file_to_inspect") strncpy_s(state.file_to_inspect, value.c_str(), sizeof(state.file_to_inspect) - 1);
                // Dumper Defaults
                else if (key == "dump_type") state.dump_type = static_cast<AppState::DumpType>(std::stoi(value));
                else if (key == "dump_optimize") state.dump_optimize = (std::stoi(value) != 0);
                else if (key == "dump_string_type") state.dump_string_type = static_cast<AppState::DumpStringType>(std::stoi(value));
                else if (key == "use_filter_list") state.use_filter_list = (std::stoi(value) != 0);
                else if (key == "filter_non_ascii") state.filter_non_ascii = (std::stoi(value) != 0);
            }
            catch (const std::invalid_argument&) { /* ignore malformed lines */ }
            catch (const std::out_of_range&) { /* ignore malformed lines */ }
        }
    }

    // After loading, check for any uninitialized forensic paths and derive them from the default directory.
    if (state.default_output_dir[0] != '\0') {
        std::filesystem::path base_path(state.default_output_dir);
        std::filesystem::path dumps_dir = base_path / "dumps";
        std::filesystem::path results_dir = base_path / "results";
        std::filesystem::path filters_dir = base_path / "filters";

        if (state.dump_output_path[0] == '\0') {
            strncpy_s(state.dump_output_path, (dumps_dir / "memory_dump.bin").string().c_str(), sizeof(state.dump_output_path) - 1);
        }
        if (state.filter_list_path[0] == '\0') {
            strncpy_s(state.filter_list_path, (filters_dir / "filter.txt").string().c_str(), sizeof(state.filter_list_path) - 1);
        }
        if (state.clean_dump_path[0] == '\0') {
            strncpy_s(state.clean_dump_path, (dumps_dir / "clean_dump.txt").string().c_str(), sizeof(state.clean_dump_path) - 1);
        }
        if (state.dirty_dump_path[0] == '\0') {
            strncpy_s(state.dirty_dump_path, (dumps_dir / "dirty_dump.txt").string().c_str(), sizeof(state.dirty_dump_path) - 1);
        }
        if (state.diff_export_path[0] == '\0') {
            strncpy_s(state.diff_export_path, (results_dir / "diff_report.txt").string().c_str(), sizeof(state.diff_export_path) - 1);
        }
    }

    // --- FIXED: Add final sync to ensure dump path extension matches the loaded dump type ---
    std::string current_path(state.dump_output_path);
    size_t dot_pos = current_path.find_last_of('.');
    if (dot_pos != std::string::npos) {
        std::string base_path = current_path.substr(0, dot_pos);
        if (state.dump_type == AppState::DUMP_TYPE_TEXT && current_path.substr(dot_pos) != ".txt") {
            strncpy_s(state.dump_output_path, (base_path + ".txt").c_str(), sizeof(state.dump_output_path) - 1);
        }
        else if (state.dump_type == AppState::DUMP_TYPE_BINARY && current_path.substr(dot_pos) != ".bin") {
            strncpy_s(state.dump_output_path, (base_path + ".bin").c_str(), sizeof(state.dump_output_path) - 1);
        }
    }
}

static std::string GetDirectoryFromPath(const std::string& filepath) {
    size_t pos = filepath.find_last_of("\\/");
    return (std::string::npos == pos) ? "" : filepath.substr(0, pos);
}
static int CALLBACK BrowseCallbackProc(HWND hwnd, UINT uMsg, LPARAM lParam, LPARAM lpData) {
    if (uMsg == BFFM_INITIALIZED) {
        SendMessage(hwnd, BFFM_SETSELECTION, TRUE, lpData);
    }
    return 0;
}
static bool BrowseForDirectory(std::string& out_path) {
    char path_buffer[MAX_PATH] = { 0 };
    BROWSEINFOA bi = { 0 };
    bi.lpszTitle = "Select Default Output Directory";
    bi.ulFlags = BIF_RETURNONLYFSDIRS | BIF_NEWDIALOGSTYLE;
    bi.lpfn = BrowseCallbackProc;
    bi.lParam = (LPARAM)out_path.c_str();

    LPITEMIDLIST pidl = SHBrowseForFolderA(&bi);
    if (pidl != NULL) {
        if (SHGetPathFromIDListA(pidl, path_buffer)) {
            out_path = path_buffer;
        }
        CoTaskMemFree(pidl);
        return true;
    }
    return false;
}


// --- Forward Declarations for Render Functions ---
static void RenderQuickScan(AppState& state, const ImVec2& contentSize);
static void RenderForensic(AppState& state, const ImVec2& contentSize);
static void RenderSettings(AppState& state, const ImVec2& contentSize);
static bool SidebarButton(const char* icon, const char* label, bool is_active, const AppState& state);
static void RenderScanAllModal(AppState& state);
static void RenderToast(AppState& state);
static void RenderElevationModal(AppState& state);


// --- Style & Color Helpers ---
static ImVec4 Grey(float v, float a = 1.0f) { return ImVec4(v, v, v, a); }
static ImVec4 WarningColor(float a = 1.0f) { return ImVec4(0.98f, 0.82f, 0.45f, a); }


void PushLog(std::vector<ColoredLine>& list, const ImVec4& color, const char* fmt, ...) {
    char buf[4096];
    va_list args;
    va_start(args, fmt);
    vsnprintf(buf, sizeof(buf), fmt, args);
    va_end(args);
    list.push_back({ color, std::string(buf) });
}

static void Separator() {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return;
    const float w = ImGui::GetContentRegionAvail().x;
    ImVec2 p = ImGui::GetCursorScreenPos();
    ImGui::Dummy(ImVec2(w, 3.0f));
    ImDrawList* dl = ImGui::GetWindowDrawList();
    p.y += 1.0f;
    dl->AddLine(ImVec2(p.x, p.y), ImVec2(p.x + w, p.y), ImGui::GetColorU32(ImGuiCol_Separator, 0.5f));
}

static bool AccentButton(const char* label, AppState& state, const ImVec2& size = ImVec2(0, 0)) {
    ImGui::PushStyleColor(ImGuiCol_Button, state.accent_color);
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImVec4(state.accent_color.x * 1.2f, state.accent_color.y * 1.2f, state.accent_color.z * 1.2f, 1.0f));
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImVec4(state.accent_color.x * 0.9f, state.accent_color.y * 0.9f, state.accent_color.z * 0.9f, 1.0f));
    const bool clicked = ImGui::Button(label, size);
    ImGui::PopStyleColor(3);
    return clicked;
}

static bool BeginCard(const char* title, const ImVec2& size = ImVec2(0, 0), bool with_separator = true, float internal_padding = 10.0f, bool scrollable = false) {
    std::string child_id = std::string(title) + "##card";
    ImGuiWindowFlags flags = 0;
    if (!scrollable) flags = ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;
    ImGui::BeginChild(child_id.c_str(), size, false, flags);
    ImGui::PushID(title);
    ImVec2 card_min = ImGui::GetWindowPos();
    ImVec2 card_max = ImVec2(card_min.x + ImGui::GetWindowWidth(), card_min.y + ImGui::GetWindowHeight());
    ImDrawList* dl = ImGui::GetWindowDrawList();
    const ImGuiStyle& st = ImGui::GetStyle();
    dl->AddRectFilled(card_min, card_max, ImGui::GetColorU32(ImGuiCol_ChildBg), st.ChildRounding);
    dl->AddRect(card_min, card_max, ImGui::GetColorU32(ImGuiCol_Border), st.ChildRounding);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(8, 8));
    ImGui::SetCursorPosX(ImGui::GetCursorPosX() + internal_padding);
    ImGui::SetCursorPosY(ImGui::GetCursorPosY() + internal_padding);
    ImGui::BeginGroup();
    ImGui::TextUnformatted(title);
    if (with_separator) Separator();
    return true;
}
static void EndCard() {
    ImGui::EndGroup();
    ImGui::PopStyleVar();
    ImGui::PopID();
    ImGui::EndChild();
}

void ApplySonarStyle(AppState& state) {
    ImGuiStyle& style = ImGui::GetStyle();
    const ImVec4& accent = state.accent_color;
    ImVec4 text_color = Grey(0.92f);
    ImVec4 bg_color_light = ImVec4(0.12f, 0.12f, 0.14f, 1.0f);
    ImVec4 bg_color = ImVec4(0.09f, 0.09f, 0.11f, 1.0f);
    ImVec4 bg_color_dark = ImVec4(0.07f, 0.07f, 0.08f, 1.0f);
    ImVec4 border_color = ImVec4(accent.x, accent.y, accent.z, 0.20f);
    style.WindowPadding = ImVec2(10, 10);
    style.FramePadding = ImVec2(10, 8);
    style.ItemSpacing = ImVec2(10, 8);
    style.ItemInnerSpacing = ImVec2(8, 6);
    style.CellPadding = ImVec2(6, 6);
    style.WindowRounding = 8.0f;
    style.ChildRounding = 8.0f;
    style.FrameRounding = 6.0f;
    style.PopupRounding = 6.0f;
    style.ScrollbarRounding = 8.0f;
    style.GrabRounding = 6.0f;
    style.TabRounding = 6.0f;
    style.Colors[ImGuiCol_Text] = text_color;
    style.Colors[ImGuiCol_TextDisabled] = Grey(0.5f);
    style.Colors[ImGuiCol_WindowBg] = bg_color;
    style.Colors[ImGuiCol_ChildBg] = bg_color;
    style.Colors[ImGuiCol_PopupBg] = bg_color_dark;
    style.Colors[ImGuiCol_Border] = border_color;
    style.Colors[ImGuiCol_BorderShadow] = ImVec4(0, 0, 0, 0);
    style.Colors[ImGuiCol_FrameBg] = bg_color_light;
    style.Colors[ImGuiCol_FrameBgHovered] = bg_color;
    style.Colors[ImGuiCol_FrameBgActive] = bg_color;
    style.Colors[ImGuiCol_TitleBg] = bg_color;
    style.Colors[ImGuiCol_TitleBgActive] = bg_color;
    style.Colors[ImGuiCol_TitleBgCollapsed] = bg_color;
    style.Colors[ImGuiCol_MenuBarBg] = bg_color;
    style.Colors[ImGuiCol_ScrollbarBg] = bg_color_dark;
    style.Colors[ImGuiCol_ScrollbarGrab] = bg_color_light;
    style.Colors[ImGuiCol_ScrollbarGrabHovered] = Grey(0.3f);
    style.Colors[ImGuiCol_ScrollbarGrabActive] = Grey(0.4f);
    style.Colors[ImGuiCol_CheckMark] = accent;
    style.Colors[ImGuiCol_SliderGrab] = accent;
    style.Colors[ImGuiCol_SliderGrabActive] = ImVec4(accent.x * 0.7f, accent.y * 0.7f, accent.z * 0.7f, 1.0f);
    style.Colors[ImGuiCol_Button] = bg_color_light;
    style.Colors[ImGuiCol_ButtonHovered] = Grey(0.2f);
    style.Colors[ImGuiCol_ButtonActive] = Grey(0.25f);
    style.Colors[ImGuiCol_Header] = bg_color_light;
    style.Colors[ImGuiCol_HeaderHovered] = Grey(0.2f);
    style.Colors[ImGuiCol_HeaderActive] = Grey(0.25f);
    style.Colors[ImGuiCol_Separator] = border_color;
    style.Colors[ImGuiCol_SeparatorHovered] = accent;
    style.Colors[ImGuiCol_SeparatorActive] = ImVec4(accent.x * 0.7f, accent.y * 0.7f, accent.z * 0.7f, 1.0f);
    style.Colors[ImGuiCol_ResizeGrip] = border_color;
    style.Colors[ImGuiCol_ResizeGripHovered] = accent;
    style.Colors[ImGuiCol_ResizeGripActive] = ImVec4(accent.x * 0.7f, accent.y * 0.7f, accent.z * 0.7f, 1.0f);
    style.Colors[ImGuiCol_Tab] = bg_color_light;
    style.Colors[ImGuiCol_TabHovered] = ImVec4(accent.x, accent.y, accent.z, 0.5f);
    style.Colors[ImGuiCol_TabActive] = accent;
    style.Colors[ImGuiCol_TabUnfocused] = bg_color_light;
    style.Colors[ImGuiCol_TabUnfocusedActive] = ImVec4(accent.x, accent.y, accent.z, 0.5f);
    style.Colors[ImGuiCol_PlotLines] = accent;
    style.Colors[ImGuiCol_PlotLinesHovered] = ImVec4(accent.x * 0.7f, accent.y * 0.7f, accent.z * 0.7f, 1.0f);
    style.Colors[ImGuiCol_PlotHistogram] = accent;
    style.Colors[ImGuiCol_PlotHistogramHovered] = ImVec4(accent.x * 0.7f, accent.y * 0.7f, accent.z * 0.7f, 1.0f);
    style.Colors[ImGuiCol_TextSelectedBg] = ImVec4(accent.x, accent.y, accent.z, 0.25f);
    style.Colors[ImGuiCol_DragDropTarget] = accent;
    style.Colors[ImGuiCol_NavHighlight] = accent;
    style.Colors[ImGuiCol_NavWindowingHighlight] = accent;
    style.Colors[ImGuiCol_NavWindowingDimBg] = ImVec4(accent.x, accent.y, accent.z, 0.2f);
    style.Colors[ImGuiCol_ModalWindowDimBg] = ImVec4(accent.x, accent.y, accent.z, 0.2f);
}


#include <algorithm> // Make sure this is included at the top of your ui.cpp

#include <algorithm> // Make sure this is included at the top of your file

#include <algorithm> // Make sure this is included at the top of your file

#include <algorithm> // Make sure this is included at the top of your file

static void RenderQuickScan(AppState& state, const ImVec2& contentSize) {
    ImGui::Columns(2, "QuickScanColumns", false);
    ImGui::SetColumnWidth(0, contentSize.x * 0.3f);

    const float top_card_height = contentSize.y * 0.65f;

    // --- LEFT COLUMN (Unchanged) ---
    if (BeginCard(ICON_FA_LIST " Process List", ImVec2(0, top_card_height))) {
        if (!state.has_debug_privilege) {
            ImGui::PushStyleColor(ImGuiCol_Text, WarningColor());
            ImGui::TextWrapped(ICON_FA_WARNING " Warning: Not running as Administrator. Process access will be limited.");
            ImGui::PopStyleColor();
            Separator();
        }

        if (ImGui::Button(ICON_FA_SYNC " Refresh")) {
            state.process_list = GetProcessList();
            state.quick_scan_selections.assign(state.process_list.size(), false);
            state.forensic_dump_selection = -1;
            state.last_quick_scan_selection = -1;
        }
        ImGui::SameLine();
        ImGui::TextDisabled("%zu processes", state.process_list.size());
        ImGui::InputTextWithHint("##filter", ICON_FA_FILTER " Filter...", state.process_filter, IM_ARRAYSIZE(state.process_filter));

        ImGui::BeginChild("ProcList", ImVec2(0, ImGui::GetContentRegionAvail().y), true);
        if (state.process_list.empty()) {
            ImGui::TextDisabled("Process list is empty. Click 'Refresh'.");
        }
        else {
            for (int i = 0; i < (int)state.process_list.size(); ++i) {
                const auto& p = state.process_list[i];
                if (state.process_filter[0] != '\0') {
                    std::string filt_lower = state.process_filter; for (auto& c : filt_lower) c = (char)tolower(c);
                    std::string disp_lower = p.display_name; for (auto& c : disp_lower) c = (char)tolower(c);
                    if (disp_lower.find(filt_lower) == std::string::npos) continue;
                }
                if (ImGui::Selectable(p.display_name.c_str(), state.quick_scan_selections[i])) {
                    if (!ImGui::GetIO().KeyCtrl && !ImGui::GetIO().KeyShift) {
                        std::fill(state.quick_scan_selections.begin(), state.quick_scan_selections.end(), false);
                        state.quick_scan_selections[i] = true;
                    }
                    else if (ImGui::GetIO().KeyShift && state.last_quick_scan_selection != -1) {
                        int start = std::min(state.last_quick_scan_selection, i);
                        int end = std::max(state.last_quick_scan_selection, i);
                        for (int j = start; j <= end; ++j) state.quick_scan_selections[j] = true;
                    }
                    else {
                        state.quick_scan_selections[i] = !state.quick_scan_selections[i];
                    }
                    state.last_quick_scan_selection = i;
                }
            }
        }
        ImGui::EndChild();
        EndCard();
    }

    ImGui::Dummy(ImVec2(0, 10));

    if (BeginCard("Selected Targets", ImVec2(0, ImGui::GetContentRegionAvail().y))) {
        int num_selected = 0;
        ImGui::BeginChild("SelectedList", ImVec2(0, ImGui::GetContentRegionAvail().y), true);
        ImVec4 selection_bg = state.accent_color;
        selection_bg.w = 0.25f;
        for (size_t i = 0; i < state.process_list.size(); ++i) {
            if (state.quick_scan_selections[i]) {
                num_selected++;
                const auto& p = state.process_list[i];
                const char* text = p.display_name.c_str();
                ImVec2 text_size = ImGui::CalcTextSize(text);
                ImVec2 cursor_pos = ImGui::GetCursorScreenPos();
                ImVec2 padding = ImGui::GetStyle().FramePadding;
                float rect_height = text_size.y + padding.y;
                ImVec2 rect_min = ImVec2(cursor_pos.x, cursor_pos.y);
                ImVec2 rect_max = ImVec2(cursor_pos.x + ImGui::GetContentRegionAvail().x, cursor_pos.y + rect_height);
                ImGui::GetWindowDrawList()->AddRectFilled(rect_min, rect_max, ImGui::GetColorU32(selection_bg), 4.0f);
                ImVec2 text_pos = ImVec2(rect_min.x + (ImGui::GetContentRegionAvail().x - text_size.x) / 2.0f, rect_min.y + (rect_height - text_size.y) / 2.0f);
                ImGui::GetWindowDrawList()->AddText(text_pos, ImGui::GetColorU32(ImGuiCol_Text), text);
                ImGui::Dummy(ImVec2(ImGui::GetContentRegionAvail().x, rect_height));
            }
        }
        if (num_selected == 0) ImGui::TextDisabled("No processes selected.");
        ImGui::EndChild();
        EndCard();
    }

    ImGui::NextColumn();

    // --- RIGHT COLUMN (Final Version) ---
    if (BeginCard(ICON_FA_SEARCH " Memory Scanner", ImVec2(0, top_card_height))) {
        // --- LAYOUT DEFINITION ---
        const float controls_row_height = 35.0f;
        const float item_spacing = ImGui::GetStyle().ItemSpacing.y;
        const float bottom_padding = 10.0f; // Breathing room at the bottom of the card

        float footer_height = controls_row_height + item_spacing + bottom_padding;

        if (state.scan_running) {
            footer_height += ImGui::GetFrameHeight() + item_spacing;
        }

        // --- SIGNATURE INPUT AREA ---
        ImGui::BeginChild("SignatureArea", ImVec2(0, -footer_height), false, ImGuiWindowFlags_NoScrollbar);
        ImGui::InputTextMultiline("##signatures", state.signature_buffer, IM_ARRAYSIZE(state.signature_buffer),
            ImVec2(-1, -1));
        ImGui::EndChild();

        // --- FOOTER AREA ---
        int num_selected = 0;
        for (bool selected : state.quick_scan_selections) if (selected) num_selected++;

        ImGui::BeginDisabled(state.scan_running);
        {
            if (ImGui::Checkbox("Case-Insensitive Scan", &state.scan_case_insensitive)) SaveSettings(state);
            ImGui::SameLine();

            const float button_width = 150.0f;
            const float buttons_total_width = button_width * 2.0f + ImGui::GetStyle().ItemSpacing.x;
            const float right_padding = 10.0f; // <-- THE FIX: Define padding for the right edge.

            // Adjust the cursor position to leave space on the right.
            ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - buttons_total_width - right_padding);

            bool no_selection = num_selected == 0;
            if (no_selection) ImGui::BeginDisabled();
            std::string scan_selected_label = "Scan Selected (" + std::to_string(num_selected) + ")";
            if (AccentButton(scan_selected_label.c_str(), state, ImVec2(button_width, controls_row_height))) {
                std::vector<ProcessInfo> targets;
                for (size_t i = 0; i < state.process_list.size(); ++i) if (state.quick_scan_selections[i]) targets.push_back(state.process_list[i]);
                if (!targets.empty()) {
                    state.scan_running = true; state.quick_scan_lines.clear(); state.scan_progress = 0.0f; state.scan_status.clear(); state.user_acknowledged_limited_scan = false;
                    PushLog(state.quick_scan_lines, state.accent_color, ICON_FA_INFO_CIRCLE " Starting scan on %zu process(es)...", targets.size());
                    auto scan_start_time = std::chrono::high_resolution_clock::now();
                    std::thread([&state, targets, scan_start_time]() {
                        auto cb = [&](float p, const std::string& m) { std::lock_guard<std::mutex> l(state.scan_progress_mutex); state.scan_progress = p; state.scan_status = m; };
                        PerformQuickScan(state, targets, state.signature_buffer, state.scan_case_insensitive, cb);
                        auto scan_end_time = std::chrono::high_resolution_clock::now();
                        auto duration = std::chrono::duration_cast<std::chrono::duration<double>>(scan_end_time - scan_start_time);
                        std::lock_guard<std::mutex> lock(state.log_mutex);
                        PushLog(state.quick_scan_lines, state.accent_color, ICON_FA_INFO_CIRCLE " Scan complete. Total elapsed time: %.2f seconds.", duration.count());
                        }).detach();
                }
            }
            if (no_selection) ImGui::EndDisabled();

            ImGui::SameLine();
            if (AccentButton(ICON_FA_SEARCH " Scan All", state, ImVec2(button_width, controls_row_height))) {
                state.show_scan_all_warning = true;
            }
        }
        ImGui::EndDisabled();

        // --- PROGRESS BAR ---
        if (state.scan_running) {
            float progress; std::string status;
            { std::lock_guard<std::mutex> lock(state.scan_progress_mutex); progress = state.scan_progress; status = state.scan_status; }
            ImGui::ProgressBar(progress, ImVec2(-1, 0), status.c_str());
        }
        EndCard();
    }

    ImGui::Dummy(ImVec2(0, 10));

    if (BeginCard(ICON_FA_CLIPBOARD " Results Log", ImVec2(0, ImGui::GetContentRegionAvail().y), true, 10.f, true)) {
        std::vector<ScanResult> new_results;
        {
            std::lock_guard<std::mutex> lock(state.scan_result_queue_mutex);
            if (!state.scan_result_queue.empty()) {
                new_results = std::move(state.scan_result_queue);
                state.scan_result_queue.clear();
            }
        }

        if (!new_results.empty()) {
            bool access_denied_on_any = false;
            for (const auto& res : new_results) if (res.signature == "[ACCESS_DENIED]") access_denied_on_any = true;

            if (access_denied_on_any && !state.has_debug_privilege && !state.user_acknowledged_limited_scan) {
                state.show_elevation_modal = true;
                state.user_acknowledged_limited_scan = true;
            }

            for (const auto& res : new_results) {
                if (res.address == 0) {
                    if (res.signature == "[ACCESS_DENIED]") PushLog(state.quick_scan_lines, ImVec4(0.98f, 0.55f, 0.55f, 1.0f), ICON_FA_TIMES_CIRCLE " Access denied to process '%s' (PID: %lu)", res.process_name.c_str(), res.pid);
                    else PushLog(state.quick_scan_lines, ImVec4(0.98f, 0.55f, 0.55f, 1.0f), ICON_FA_TIMES_CIRCLE " %s for process '%s' (PID: %lu)", res.signature.c_str(), res.process_name.c_str(), res.pid);
                }
                else {
                    PushLog(state.quick_scan_lines, ImVec4(0.98f, 0.82f, 0.45f, 1.0f), ICON_FA_SEARCH " Found '%s' in '%s' (PID: %lu) at 0x%p", res.signature.c_str(), res.process_name.c_str(), res.pid, (void*)res.address);
                }
            }
        }

        if (!state.scan_running && state.clear_signatures_on_complete && state.signature_buffer[0] != '\0') {
            if (strlen(state.signature_buffer) > 0) {
                state.signature_buffer[0] = '\0';
                PushLog(state.quick_scan_lines, state.accent_color, ICON_FA_INFO_CIRCLE " Signature buffer cleared as per settings.");
            }
        }

        for (const auto& l : state.quick_scan_lines) {
            ImGui::PushStyleColor(ImGuiCol_Text, l.color);
            ImGui::TextWrapped("%s", l.text.c_str());
            ImGui::PopStyleColor();
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
        EndCard();
    }
    ImGui::Columns(1);
}


static void RenderForensic(AppState& state, const ImVec2& contentSize) {
    ImGui::Columns(2, "ForensicColumns", false);
    const float left_col_width = contentSize.x * 0.5f - 5;
    ImGui::SetColumnWidth(0, left_col_width);

    const float top_card_height = contentSize.y * 0.55f;
    const float item_spacing = ImGui::GetStyle().ItemSpacing.y;

    // --- LEFT COLUMN ---
    if (BeginCard(ICON_FA_DATABASE " Memory Dumper", ImVec2(0, top_card_height), true, 10.0f, true)) {
        ImGui::InputTextWithHint("##dumper_filter", ICON_FA_FILTER " Filter processes...", state.forensic_process_filter, IM_ARRAYSIZE(state.forensic_process_filter));
        ImGui::SameLine();
        if (ImGui::Button(ICON_FA_SYNC " Refresh")) {
            state.process_list = GetProcessList();
            state.quick_scan_selections.assign(state.process_list.size(), false);
            state.last_quick_scan_selection = -1;
            state.forensic_dump_selection = -1;
        }

        float list_height = ImGui::GetTextLineHeightWithSpacing() * 5;
        ImGui::BeginChild("dumper_proc_list", ImVec2(0, list_height), true);
        if (state.process_list.empty()) ImGui::TextDisabled("Process list is empty.");
        else {
            for (int i = 0; i < (int)state.process_list.size(); ++i) {
                const auto& p = state.process_list[i];
                if (state.forensic_process_filter[0] != '\0') {
                    std::string filt_lower = state.forensic_process_filter; for (auto& c : filt_lower) c = (char)tolower(c);
                    std::string disp_lower = p.display_name; for (auto& c : disp_lower) c = (char)tolower(c);
                    if (disp_lower.find(filt_lower) == std::string::npos) continue;
                }
                if (ImGui::Selectable(p.display_name.c_str(), state.forensic_dump_selection == i)) state.forensic_dump_selection = i;
            }
        }
        ImGui::EndChild();
        ImGui::Spacing();

        const ImGuiStyle& style = ImGui::GetStyle();
        float folder_button_width = ImGui::CalcTextSize(ICON_FA_FOLDER_OPEN).x + style.FramePadding.x * 2.0f;
        // --- FIXED: Subtracted an extra item spacing to create padding on the right of the button ---
        float input_width = ImGui::GetContentRegionAvail().x - folder_button_width - (style.ItemSpacing.x * 2.0f);
        ImGui::PushItemWidth(input_width);
        ImGui::InputTextWithHint("##dump_path", ICON_FA_FLOPPY_DISK " C:\\temp\\memory_dump.bin", state.dump_output_path, IM_ARRAYSIZE(state.dump_output_path));
        ImGui::PopItemWidth();
        ImGui::SameLine();
        if (ImGui::Button(ICON_FA_FOLDER_OPEN)) {
            std::string dir = GetDirectoryFromPath(state.dump_output_path);
            if (!dir.empty()) ShellExecuteA(NULL, "open", dir.c_str(), NULL, NULL, SW_SHOWDEFAULT);
        }

        ImGui::AlignTextToFramePadding();
        ImGui::Text("Dump Type:"); ImGui::SameLine();
        if (ImGui::RadioButton("Binary", (int*)&state.dump_type, AppState::DUMP_TYPE_BINARY)) {
            std::string current_path(state.dump_output_path);
            size_t dot_pos = current_path.find_last_of('.');
            if (dot_pos != std::string::npos && current_path.substr(dot_pos) == ".txt") {
                std::string base_path = current_path.substr(0, dot_pos);
                strncpy_s(state.dump_output_path, (base_path + ".bin").c_str(), sizeof(state.dump_output_path) - 1);
            }
        }
        ImGui::SameLine();
        if (ImGui::RadioButton("Text (Strings)", (int*)&state.dump_type, AppState::DUMP_TYPE_TEXT)) {
            std::string current_path(state.dump_output_path);
            size_t dot_pos = current_path.find_last_of('.');
            if (dot_pos != std::string::npos && current_path.substr(dot_pos) == ".bin") {
                std::string base_path = current_path.substr(0, dot_pos);
                strncpy_s(state.dump_output_path, (base_path + ".txt").c_str(), sizeof(state.dump_output_path) - 1);
            }
        }

        if (state.dump_type == AppState::DUMP_TYPE_BINARY) {
            ImGui::Checkbox("Optimize", &state.dump_optimize);
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("For binary dumps only. Skips writing identical pages of memory.");
        }

        if (state.dump_type == AppState::DUMP_TYPE_TEXT) {
            Separator();
            ImGui::RadioButton("ASCII", (int*)&state.dump_string_type, AppState::DUMP_ASCII_ONLY); ImGui::SameLine();
            ImGui::RadioButton("Unicode", (int*)&state.dump_string_type, AppState::DUMP_UNICODE_ONLY); ImGui::SameLine();
            ImGui::RadioButton("Both", (int*)&state.dump_string_type, AppState::DUMP_BOTH);

            ImGui::Checkbox("Use Filter List", &state.use_filter_list); ImGui::SameLine();
            ImGui::Checkbox("Filter Non-ASCII", &state.filter_non_ascii);

            ImGui::PushItemWidth(-style.ItemSpacing.x);
            ImGui::InputTextWithHint("##filter_path", "Filter File Path...", state.filter_list_path, IM_ARRAYSIZE(state.filter_list_path));
            ImGui::PopItemWidth();
        }

        ImGui::Dummy(ImVec2(0, 5.0f));
        const float button_width = 180.0f;
        const float button_height = 35.0f;
        float group_width = button_width;
        if (!state.has_debug_privilege) group_width += ImGui::CalcTextSize(ICON_FA_EXCLAMATION_TRIANGLE).x + style.ItemInnerSpacing.x;

        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + ImGui::GetContentRegionAvail().x - group_width - style.WindowPadding.x);
        float group_start_y = ImGui::GetCursorPosY();

        if (!state.has_debug_privilege) {
            float icon_y_offset = (button_height - ImGui::GetTextLineHeight()) / 2.0f;
            ImGui::SetCursorPosY(group_start_y + icon_y_offset);
            ImGui::PushStyleColor(ImGuiCol_Text, WarningColor());
            ImGui::Text(ICON_FA_EXCLAMATION_TRIANGLE);
            ImGui::PopStyleColor();
            if (ImGui::IsItemHovered()) ImGui::SetTooltip("Warning: SeDebugPrivilege not enabled.\nOnly processes with lower permissions can be dumped.");
            ImGui::SameLine(0.0f, style.ItemInnerSpacing.x);
        }

        ImGui::SetCursorPosY(group_start_y);
        const bool dump_button_disabled = state.dump_running || state.forensic_dump_selection < 0;
        if (dump_button_disabled) ImGui::BeginDisabled();
        if (AccentButton(ICON_FA_FLOPPY_DISK " Create Dump", state, ImVec2(button_width, button_height))) {
            state.dump_running = true; state.dump_progress = 0.0f;
            ProcessInfo target_process = state.process_list[state.forensic_dump_selection];
            PushLog(state.forensic_log_lines, state.accent_color, "[DUMP] Starting dump for %s...", target_process.display_name.c_str());
            std::thread([&state, target_process]() {
                auto cb = [&](float p, const std::string& m) { std::lock_guard<std::mutex> l(state.dump_progress_mutex); state.dump_progress = p; state.dump_status = m; };
                auto [success, message] = CreateManualMemoryDump(target_process.pid, state.dump_output_path, state.dump_optimize, (state.dump_type == AppState::DUMP_TYPE_TEXT), state.dump_string_type, state.filter_list_path, state.use_filter_list, state.filter_non_ascii, cb);
                std::lock_guard<std::mutex> lock(state.log_mutex);
                if (!success && message == "[ACCESS_DENIED]") state.show_elevation_modal = true;
                else PushLog(state.forensic_log_lines, success ? ImVec4(0.7f, 0.95f, 0.7f, 1.0f) : ImVec4(0.98f, 0.55f, 0.55f, 1.0f), "[DUMP] %s", message.c_str());
                state.dump_running = false;
                }).detach();
        }
        if (dump_button_disabled) ImGui::EndDisabled();

        if (state.dump_running) {
            ImGui::Dummy(ImVec2(0, 5));
            float progress; std::string status;
            { std::lock_guard<std::mutex> lock(state.dump_progress_mutex); progress = state.dump_progress; status = state.dump_status; }
            ImGui::ProgressBar(progress, ImVec2(-1, 0), status.c_str());
        }
        ImGui::Dummy(ImVec2(0, 5));
        EndCard();
    }

    ImGui::Dummy(ImVec2(0, item_spacing));

    if (BeginCard(ICON_FA_EXCHANGE_ALT " Differential Analyzer", ImVec2(0, ImGui::GetContentRegionAvail().y), true, 10.f, true)) {
        ImGui::PushItemWidth(-ImGui::GetStyle().ItemSpacing.x);
        ImGui::InputTextWithHint("##clean_path", ICON_FA_FILE_CODE " Clean Dump Path...", state.clean_dump_path, IM_ARRAYSIZE(state.clean_dump_path));
        ImGui::InputTextWithHint("##dirty_path", ICON_FA_FILE_CODE " Dirty Dump Path...", state.dirty_dump_path, IM_ARRAYSIZE(state.dirty_dump_path));
        ImGui::PopItemWidth();
        ImGui::Dummy(ImVec2(0, 5));

        bool diff_button_disabled = state.diff_running || state.clean_dump_path[0] == '\0' || state.dirty_dump_path[0] == '\0';
        if (diff_button_disabled) ImGui::BeginDisabled();
        ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x - 180.0f - ImGui::GetStyle().WindowPadding.x);
        if (AccentButton(ICON_FA_SEARCH " Compare Dumps", state, ImVec2(180, 35))) {
            state.diff_running = true; state.new_diff_results_ready = false; state.diff_progress = 0.0f;
            PushLog(state.forensic_log_lines, state.accent_color, "[DIFF] Starting analysis...");
            std::thread([&state]() {
                auto progress_callback = [&](float progress) { std::lock_guard<std::mutex> lock(state.diff_progress_mutex); state.diff_progress = progress; };
                DiffResult results = PerformDifferentialAnalysis(state.clean_dump_path, state.dirty_dump_path, progress_callback);
                std::lock_guard<std::mutex> lock(state.log_mutex);
                state.diff_result = results; state.new_diff_results_ready = true; state.diff_running = false;
                if (!results.error.empty()) PushLog(state.forensic_log_lines, ImVec4(0.98f, 0.55f, 0.55f, 1.0f), "[DIFF] %s", results.error.c_str());
                else PushLog(state.forensic_log_lines, ImVec4(0.7f, 0.95f, 0.7f, 1.0f), "[DIFF] Analysis complete. Found %zu new strings and %zu modified regions.", results.new_strings.size(), results.modified_regions.size());
                }).detach();
        }
        if (diff_button_disabled) ImGui::EndDisabled();
        Separator();
        if (state.diff_running) {
            float progress; { std::lock_guard<std::mutex> lock(state.diff_progress_mutex); progress = state.diff_progress; }
            char buf[64]; snprintf(buf, sizeof(buf), "Analyzing... %.0f%%", progress * 100);
            ImGui::ProgressBar(progress, ImVec2(-1, 0), buf);
        }
        else if (state.new_diff_results_ready) {
            float export_button_width = ImGui::CalcTextSize("Export").x + ImGui::GetStyle().FramePadding.x * 2.0f;
            ImGui::PushItemWidth(ImGui::GetContentRegionAvail().x - export_button_width - ImGui::GetStyle().ItemSpacing.x);
            ImGui::InputTextWithHint("##export_path", "Export File Path...", state.diff_export_path, IM_ARRAYSIZE(state.diff_export_path));
            ImGui::PopItemWidth();
            ImGui::SameLine();
            if (AccentButton("Export", state)) {
                auto [success, message] = ExportDiffResults(state.diff_result, state.diff_export_path);
                ImVec4 color = success ? ImVec4(0.7f, 0.95f, 0.7f, 1.0f) : ImVec4(0.98f, 0.55f, 0.55f, 1.0f); PushLog(state.forensic_log_lines, color, "[EXPORT] %s", message.c_str());
            }
            if (ImGui::BeginTabBar("DiffResultsBar")) {
                std::string strings_label = "New Strings (" + std::to_string(state.diff_result.new_strings.size()) + ")";
                if (ImGui::BeginTabItem(strings_label.c_str())) {
                    if (ImGui::Button("Copy to Clipboard##Strings")) {
                        std::stringstream ss; for (const auto& str : state.diff_result.new_strings) ss << str << "\n";
                        ImGui::SetClipboardText(ss.str().c_str());
                    }
                    ImGui::BeginChild("StringsList", ImVec2(0, 0), true);
                    for (const auto& str : state.diff_result.new_strings) ImGui::TextUnformatted(str.c_str());
                    ImGui::EndChild();
                    ImGui::EndTabItem();
                }
                if (!state.diff_result.modified_regions.empty()) {
                    std::string regions_label = "Modified Regions (" + std::to_string(state.diff_result.modified_regions.size()) + ")";
                    if (ImGui::BeginTabItem(regions_label.c_str())) {
                        if (ImGui::BeginTable("RegionsTable", 3, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                            ImGui::TableSetupColumn("Offset"); ImGui::TableSetupColumn("Size"); ImGui::TableSetupColumn("Hashes (Clean -> Dirty)"); ImGui::TableHeadersRow();
                            for (const auto& region : state.diff_result.modified_regions) {
                                ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::Text("0x%llX", region.offset); ImGui::TableNextColumn(); ImGui::Text("%zu bytes", region.size); ImGui::TableNextColumn();
                                std::stringstream ss; ss << "0x" << std::hex << region.clean_hash << " -> 0x" << region.dirty_hash; ImGui::Text("%s", ss.str().c_str());
                            }
                            ImGui::EndTable();
                        }
                        ImGui::EndTabItem();
                    }
                }
                ImGui::EndTabBar();
            }
        }
        else ImGui::TextDisabled("Click 'Compare Dumps' to see results.");
        EndCard();
    }

    ImGui::NextColumn();

    // --- RIGHT COLUMN ---
    if (BeginCard(ICON_FA_SEARCH " PE File Inspector", ImVec2(0, top_card_height))) {
        ImGui::PushItemWidth(-ImGui::GetStyle().ItemSpacing.x);
        ImGui::InputTextWithHint("##file_path_inspect", ICON_FA_FILE_CODE " File Path (drag/drop)...", state.file_to_inspect, IM_ARRAYSIZE(state.file_to_inspect));
        ImGui::PopItemWidth();
        if (ImGui::BeginDragDropTarget()) {
            if (const ImGuiPayload* payload = ImGui::AcceptDragDropPayload("DND_FILE_PATH")) {
                const char* path = (const char*)payload->Data;
                std::lock_guard<std::mutex> lock(state.drop_mutex);
                state.path_to_drop = path;
            }
            ImGui::EndDragDropTarget();
        }

        ImGui::Dummy(ImVec2(0, 5));
        const bool inspect_button_disabled = (state.file_to_inspect[0] == '\0');
        if (inspect_button_disabled) ImGui::BeginDisabled();
        ImGui::SetCursorPosX(ImGui::GetContentRegionMax().x - 180.0f - ImGui::GetStyle().WindowPadding.x);
        if (AccentButton("Inspect File", state, ImVec2(180, 35))) {
            state.pe_info = InspectPEFile(state.file_to_inspect);
            PushLog(state.forensic_log_lines, state.accent_color, "[PE] Inspected '%s'.", state.file_to_inspect);
        }
        if (inspect_button_disabled) ImGui::EndDisabled();
        Separator();
        if (!state.pe_info.file_path.empty()) {
            if (!state.pe_info.error.empty()) ImGui::TextColored(ImVec4(0.98f, 0.55f, 0.55f, 1.0f), "%s", state.pe_info.error.c_str());
            else {
                ImGui::Text("Arch:"); ImGui::SameLine(); ImGui::TextDisabled("%s", state.pe_info.architecture.c_str());
                ImGui::Text("Compile Time:"); ImGui::SameLine(); ImGui::TextDisabled("%s", state.pe_info.compile_time.c_str());
                ImGui::SameLine();
                if (ImGui::Button(ICON_FA_COPY "##copytime")) ImGui::SetClipboardText(state.pe_info.compile_time.c_str());
                if (ImGui::IsItemHovered()) ImGui::SetTooltip("Copy timestamp to clipboard");

                if (ImGui::BeginTable("SectionsTable", 4, ImGuiTableFlags_Borders | ImGuiTableFlags_RowBg | ImGuiTableFlags_ScrollY)) {
                    ImGui::TableSetupColumn("Name"); ImGui::TableSetupColumn("Address"); ImGui::TableSetupColumn("Size"); ImGui::TableSetupColumn("Flags"); ImGui::TableHeadersRow();
                    for (const auto& section : state.pe_info.sections) {
                        ImGui::TableNextRow(); ImGui::TableNextColumn(); ImGui::Text("%s", section.name.c_str());
                        ImGui::TableNextColumn(); ImGui::Text("0x%08X", section.virtual_address);
                        ImGui::TableNextColumn(); ImGui::Text("%u", section.size_of_raw_data);
                        ImGui::TableNextColumn();
                        std::string flags;
                        if (section.characteristics & 0x20000000) flags += "X ";
                        if (section.characteristics & 0x40000000) flags += "R ";
                        if (section.characteristics & 0x80000000) flags += "W ";
                        ImGui::Text("%s", flags.c_str());
                    }
                    ImGui::EndTable();
                }
            }
        }
        else ImGui::TextDisabled("Select a PE file to inspect.");
        EndCard();
    }

    ImGui::Dummy(ImVec2(0, item_spacing));

    if (BeginCard(ICON_FA_CLIPBOARD " Forensic Log", ImVec2(0, ImGui::GetContentRegionAvail().y), true, 10.f, true)) {
        if (state.forensic_log_lines.empty()) ImGui::TextDisabled("Logs from Forensic Toolkit actions will appear here.");
        else {
            for (const auto& line : state.forensic_log_lines) {
                ImGui::PushStyleColor(ImGuiCol_Text, line.color);
                ImGui::TextWrapped("%s", line.text.c_str());
                ImGui::PopStyleColor();
            }
        }
        if (ImGui::GetScrollY() >= ImGui::GetScrollMaxY()) ImGui::SetScrollHereY(1.0f);
        EndCard();
    }
    ImGui::Columns(1);
}

static void RenderSettings(AppState& state, const ImVec2& contentSize) {
    // Begin a single, scrollable card that takes up the entire content area.
    // The last parameter 'true' enables scrolling.
    if (BeginCard(ICON_FA_COG " Application Settings", contentSize, true, 10.0f, true)) {

        // --- WORKFLOW SECTION ---
        ImGui::Text("Workflow & Defaults");
        Separator();
        ImGui::Dummy(ImVec2(0, 5.0f));

        ImGui::Text("Default Output Directory");
        const ImGuiStyle& style = ImGui::GetStyle();
        float browse_button_width = ImGui::CalcTextSize("Browse...").x + style.FramePadding.x * 2.0f;
        float input_width = ImGui::GetContentRegionAvail().x - browse_button_width - style.ItemSpacing.x;
        ImGui::PushItemWidth(input_width);
        ImGui::InputText("##outdir", state.default_output_dir, sizeof(state.default_output_dir));
        ImGui::PopItemWidth();
        ImGui::SameLine();
        if (ImGui::Button("Browse...##outdir")) {
            std::string path = state.default_output_dir;
            if (BrowseForDirectory(path)) {
                strncpy_s(state.default_output_dir, path.c_str(), sizeof(state.default_output_dir) - 1);
            }
        }

        ImGui::Dummy(ImVec2(0, 5.0f));
        ImGui::Text("Default Memory Dumper Options");
        ImGui::RadioButton("Binary", (int*)&state.dump_type, AppState::DUMP_TYPE_BINARY); ImGui::SameLine();
        ImGui::RadioButton("Text (Strings)", (int*)&state.dump_type, AppState::DUMP_TYPE_TEXT);
        ImGui::Checkbox("Optimize binary dumps (skip identical pages)", &state.dump_optimize);
        ImGui::Checkbox("Use filter list for text dumps", &state.use_filter_list);
        ImGui::Checkbox("Filter non-ASCII characters from text dumps", &state.filter_non_ascii);

        ImGui::Dummy(ImVec2(0, 5.0f));
        ImGui::Checkbox("Clear signatures text box after each quick scan", &state.clear_signatures_on_complete);
        ImGui::Checkbox("Quick scan is case-insensitive by default", &state.scan_case_insensitive);
        ImGui::Dummy(ImVec2(0, 15.0f));


        // --- PERFORMANCE SECTION ---
        ImGui::Text(ICON_FA_MICROCHIP " Performance");
        Separator();
        ImGui::Dummy(ImVec2(0, 5.0f));

        int max_threads = std::thread::hardware_concurrency();
        ImGui::SliderInt("Scanner Threads", &state.scanner_thread_count, 1, max_threads);
        if (ImGui::IsItemHovered()) ImGui::SetTooltip("Controls how many CPU threads to use for memory scanning.\nYour system has %d threads.", max_threads);
        ImGui::Dummy(ImVec2(0, 15.0f));


        // --- APPEARANCE SECTION ---
        ImGui::Text(ICON_FA_PAINT_BRUSH " Appearance");
        Separator();
        ImGui::Dummy(ImVec2(0, 5.0f));

        if (ImGui::ColorEdit3("Accent Color", (float*)&state.accent_color)) {
            ApplySonarStyle(state);
        }
        ImGui::Checkbox("Enable subtle animations (UI only)", &state.settings_enable_animations);
        ImGui::Dummy(ImVec2(0, 20.0f));


        // --- CONSOLIDATED SAVE BUTTON ---
        if (AccentButton("Save All Settings", state, ImVec2(ImGui::GetContentRegionAvail().x, 35.0f))) {
            SaveSettings(state);
            // You could add a toast notification here to confirm saving
        }

        EndCard();
    }
}


static bool SidebarButton(const char* icon, const char* label, bool is_active, const AppState& state) {
    ImGuiWindow* window = ImGui::GetCurrentWindow();
    if (window->SkipItems) return false;
    ImGuiContext& g = *GImGui;
    const ImGuiStyle& style = g.Style;
    std::string hidden_id = std::string(label) + "##sidebar";
    const ImGuiID id = window->GetID(hidden_id.c_str());
    const ImVec2 label_size = ImGui::CalcTextSize(label, NULL, true);
    ImVec2 pos = window->DC.CursorPos;
    ImVec2 size = ImVec2(ImGui::GetContentRegionAvail().x, label_size.y + style.FramePadding.y * 2.0f);
    const ImRect bb(pos, pos + size);
    ImGui::ItemSize(size, style.FramePadding.y);
    if (!ImGui::ItemAdd(bb, id)) return false;
    bool hovered, held;
    const bool pressed = ImGui::ButtonBehavior(bb, id, &hovered, &held, 0);
    const ImU32 col = ImGui::GetColorU32((held && hovered) ? ImGuiCol_ButtonActive : hovered ? ImGuiCol_ButtonHovered : ImGuiCol_Button);
    ImGui::RenderFrame(bb.Min, bb.Max, col, true, style.FrameRounding);

    if (is_active) {
        ImDrawList* dl = ImGui::GetWindowDrawList();
        ImVec4 accent = state.accent_color;
        if (state.settings_enable_animations) {
            float sine = 0.5f * sinf(6.0f * (float)ImGui::GetTime()) + 0.5f;
            accent.w = 0.7f + 0.3f * sine;
        }
        dl->AddRectFilled(ImVec2(bb.Min.x, bb.Min.y), ImVec2(bb.Min.x + 4, bb.Max.y), ImGui::GetColorU32(accent), style.FrameRounding);
    }

    std::string text = std::string(icon) + "   " + label;
    ImGui::RenderTextClipped(bb.Min + style.FramePadding, bb.Max - style.FramePadding, text.c_str(), NULL, NULL, style.ButtonTextAlign, &bb);
    return pressed;
}

void RenderUI(AppState& state, GLFWwindow* window) {
    const ImGuiViewport* viewport = ImGui::GetMainViewport();
    ImGui::SetNextWindowPos(viewport->WorkPos);
    ImGui::SetNextWindowSize(viewport->WorkSize);

    ImGuiWindowFlags flags = ImGuiWindowFlags_NoTitleBar | ImGuiWindowFlags_NoResize | ImGuiWindowFlags_NoMove |
        ImGuiWindowFlags_NoCollapse | ImGuiWindowFlags_NoSavedSettings | ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse;

    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(0, 0));
    ImGui::PushStyleVar(ImGuiStyleVar_WindowBorderSize, 0.0f);
    ImGui::Begin("SonarMainWindow", NULL, flags);
    ImGui::PopStyleVar(2);

    const float titleBarHeight = 50.0f;
    const ImVec2 windowPos = ImGui::GetWindowPos();
    const ImVec2 windowSize = ImGui::GetWindowSize();
    ImDrawList* drawList = ImGui::GetWindowDrawList();
    drawList->AddRectFilled(windowPos, ImVec2(windowPos.x + windowSize.x, windowPos.y + titleBarHeight), ImGui::GetColorU32(ImGuiCol_MenuBarBg));

    ImGui::SetCursorPos(ImVec2(12, 12));
    ImGui::PushFont(ImGui::GetIO().Fonts->Fonts[0]);
    ImGui::TextColored(state.accent_color, "Sonar");
    ImGui::SameLine(0, 4);
    ImGui::Text("Toolkit");
    ImGui::PopFont();

    ImGui::SetCursorPos(ImVec2(windowSize.x - 80, 0));
    ImGui::BeginGroup();
    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, ImGui::GetStyle().Colors[ImGuiCol_ButtonHovered]);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, ImGui::GetStyle().Colors[ImGuiCol_ButtonActive]);
    ImGui::PushStyleVar(ImGuiStyleVar_FrameBorderSize, 0.0f);
    ImGui::PushStyleVar(ImGuiStyleVar_FramePadding, ImVec2(8, 8));
    if (ImGui::Button("_", ImVec2(40, titleBarHeight))) glfwIconifyWindow(window);
    ImGui::SameLine(0, 0);
    if (ImGui::Button("X", ImVec2(40, titleBarHeight))) glfwSetWindowShouldClose(window, true);
    ImGui::PopStyleColor(3);
    ImGui::PopStyleVar(2);
    ImGui::EndGroup();
    ImGui::SetCursorPos(ImVec2(0, 0));
    ImGui::InvisibleButton("##titleBarDrag", ImVec2(windowSize.x - 80, titleBarHeight));
    if (ImGui::IsItemActive() && ImGui::IsMouseDragging(ImGuiMouseButton_Left)) {
        int x, y; glfwGetWindowPos(window, &x, &y);
        x += (int)ImGui::GetIO().MouseDelta.x; y += (int)ImGui::GetIO().MouseDelta.y;
        glfwSetWindowPos(window, x, y);
    }

    ImGui::SetCursorPos(ImVec2(0, titleBarHeight));

    const float sidebar_width = 240.0f;
    const float toast_height_value = 85.0f;
    const float toast_height = (state.show_admin_toast && !state.toast_dismissed) ? toast_height_value : 0.0f;
    const float bottom_margin = 10.0f;
    const float main_content_height = ImGui::GetContentRegionAvail().y - toast_height - bottom_margin;

    ImGui::BeginChild("MainContent", ImVec2(0, main_content_height), false, ImGuiWindowFlags_NoScrollbar);
    ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(0, 0));
    ImGui::BeginChild("Sidebar", ImVec2(sidebar_width, 0), false, ImGuiWindowFlags_NoScrollbar);
    {
        ImGui::SetCursorPosY(ImGui::GetCursorPosY() + 20);
        ImGui::PushStyleVar(ImGuiStyleVar_FrameRounding, 4.0f);
        ImGui::PushStyleVar(ImGuiStyleVar_ItemSpacing, ImVec2(10, 10));
        ImGui::SetCursorPosX(ImGui::GetCursorPosX() + 15);
        ImGui::BeginGroup();
        if (SidebarButton(ICON_FA_SEARCH, "Quick Scan", state.active_panel == AppState::PANEL_QUICK_SCAN, state)) state.active_panel = AppState::PANEL_QUICK_SCAN;
        if (SidebarButton(ICON_FA_WRENCH, "Forensic Toolkit", state.active_panel == AppState::PANEL_FORENSIC, state)) state.active_panel = AppState::PANEL_FORENSIC;
        if (SidebarButton(ICON_FA_COG, "Settings", state.active_panel == AppState::PANEL_SETTINGS, state)) state.active_panel = AppState::PANEL_SETTINGS;
        ImGui::EndGroup();
        ImGui::PopStyleVar(2);
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();

    ImGui::SameLine();

    const float contentPadding = 20.0f;
    ImGui::PushStyleVar(ImGuiStyleVar_WindowPadding, ImVec2(contentPadding, contentPadding));
    ImGui::BeginChild("Content", ImVec2(0, 0), false);
    {
        {
            std::lock_guard<std::mutex> lock(state.drop_mutex);
            if (!state.path_to_drop.empty()) {
                strncpy_s(state.file_to_inspect, state.path_to_drop.c_str(), sizeof(state.file_to_inspect) - 1);
                state.path_to_drop.clear();
            }
        }
        ImVec2 contentSize = ImGui::GetContentRegionAvail();
        switch (state.active_panel) {
        case AppState::PANEL_QUICK_SCAN: RenderQuickScan(state, contentSize); break;
        case AppState::PANEL_FORENSIC:   RenderForensic(state, contentSize);  break;
        case AppState::PANEL_SETTINGS:   RenderSettings(state, contentSize);  break;
        }
    }
    ImGui::EndChild();
    ImGui::PopStyleVar();
    ImGui::EndChild();

    RenderToast(state);

    ImGui::End();

    RenderScanAllModal(state);
    RenderElevationModal(state);
}

static void RenderToast(AppState& state) {
    if (!state.show_admin_toast || state.toast_dismissed) return;

    const float toast_height = 85.0f;
    ImGui::BeginChild("Toast", ImVec2(0, toast_height), false, ImGuiWindowFlags_NoScrollbar | ImGuiWindowFlags_NoScrollWithMouse | ImGuiWindowFlags_NoTitleBar);

    ImDrawList* dl = ImGui::GetWindowDrawList();
    ImVec2 p_min = ImGui::GetWindowPos();
    ImVec2 p_max = ImVec2(p_min.x + ImGui::GetWindowWidth(), p_min.y + ImGui::GetWindowHeight());
    ImVec4 accent_bg = state.accent_color;
    accent_bg.w = 0.2f;
    ImVec4 accent_line = state.accent_color;
    accent_line.w = 0.5f;
    dl->AddRectFilled(p_min, p_max, ImGui::GetColorU32(accent_bg));
    dl->AddLine(p_min, ImVec2(p_max.x, p_min.y), ImGui::GetColorU32(accent_line));

    const float button_height = 30.0f;
    float text_v_center = (toast_height - ImGui::GetTextLineHeight()) / 2.0f;
    float button_v_center = (toast_height - button_height) / 2.0f;

    ImGui::SetCursorPos(ImVec2(20, text_v_center));
    ImGui::PushStyleColor(ImGuiCol_Text, state.accent_color);
    ImGui::Text(ICON_FA_WARNING);
    ImGui::PopStyleColor();
    ImGui::SameLine();
    ImGui::Text("Administrator privileges are required for full functionality.");

    const float button_width = 100.0f;
    const float buttons_total_width = button_width * 2 + ImGui::GetStyle().ItemSpacing.x;
    ImGui::SameLine(ImGui::GetWindowWidth() - buttons_total_width - ImGui::GetStyle().WindowPadding.x);
    ImGui::SetCursorPosY(button_v_center);

    ImVec4 hover_color = state.accent_color;
    hover_color.w = 0.3f;
    ImVec4 active_color = state.accent_color;
    active_color.w = 0.4f;

    ImGui::PushStyleColor(ImGuiCol_Button, ImVec4(0, 0, 0, 0));
    ImGui::PushStyleColor(ImGuiCol_ButtonHovered, hover_color);
    ImGui::PushStyleColor(ImGuiCol_ButtonActive, active_color);
    ImGui::PushStyleColor(ImGuiCol_Text, Grey(0.8f));
    if (ImGui::Button("Dismiss", ImVec2(button_width, button_height))) state.toast_dismissed = true;
    ImGui::PopStyleColor(4);

    ImGui::SameLine();
    ImGui::SetCursorPosY(button_v_center);
    if (AccentButton(ICON_FA_SHIELD_ALT " Elevate", state, ImVec2(button_width, button_height))) {
        state.elevation_requested = true;
    }
    ImGui::EndChild();
}

static void RenderScanAllModal(AppState& state) {
    // Set the position before opening the popup
    if (state.show_scan_all_warning) {
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        ImGui::OpenPopup("Scan All Warning");
    }

    if (ImGui::BeginPopupModal("Scan All Warning", &state.show_scan_all_warning, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text(ICON_FA_EXCLAMATION_TRIANGLE " Are you sure?");
        Separator();
        ImGui::Dummy(ImVec2(0, 5));
        ImGui::TextWrapped("Scanning all running processes can be very resource-intensive and take a long time.");
        ImGui::TextWrapped("Additionally, you may encounter errors for protected system processes if Sonar is not run with administrator privileges.");
        ImGui::Dummy(ImVec2(0, 10));
        if (ImGui::Button("Cancel", ImVec2(120, 0))) {
            state.show_scan_all_warning = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (AccentButton(ICON_FA_SEARCH " Confirm & Scan", state, ImVec2(180, 0))) {
            state.scan_running = true; state.quick_scan_lines.clear(); state.scan_progress = 0.0f; state.scan_status.clear(); state.user_acknowledged_limited_scan = false;
            PushLog(state.quick_scan_lines, state.accent_color, ICON_FA_INFO_CIRCLE " Starting scan on all %zu process(es)...", state.process_list.size());

            auto scan_start_time = std::chrono::high_resolution_clock::now();

            std::thread([&state, scan_start_time]() {
                auto cb = [&](float p, const std::string& m) { std::lock_guard<std::mutex> l(state.scan_progress_mutex); state.scan_progress = p; state.scan_status = m; };
                PerformQuickScan(state, state.process_list, state.signature_buffer, state.scan_case_insensitive, cb);

                auto scan_end_time = std::chrono::high_resolution_clock::now();
                auto duration = std::chrono::duration_cast<std::chrono::duration<double>>(scan_end_time - scan_start_time);

                std::lock_guard<std::mutex> lock(state.log_mutex);
                PushLog(state.quick_scan_lines, state.accent_color, ICON_FA_INFO_CIRCLE " Scan complete. Total elapsed time: %.2f seconds.", duration.count());

                }).detach();
            state.show_scan_all_warning = false;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}

static void RenderElevationModal(AppState& state) {
    // Set the position before opening the popup
    if (state.show_elevation_modal) {
        ImVec2 center = ImGui::GetMainViewport()->GetCenter();
        ImGui::SetNextWindowPos(center, ImGuiCond_Appearing, ImVec2(0.5f, 0.5f));
        ImGui::OpenPopup("Elevation Required");
        state.show_elevation_modal = false;
    }

    // NULL check for BeginPopupModal is important as it returns false until the popup is open
    if (ImGui::BeginPopupModal("Elevation Required", NULL, ImGuiWindowFlags_AlwaysAutoResize)) {
        ImGui::Text(ICON_FA_SHIELD_ALT " Administrator Privileges Needed");
        Separator();
        ImGui::Dummy(ImVec2(0, 5));
        ImGui::TextWrapped("Access to one or more processes was denied. To scan these, Sonar needs admin rights.");
        ImGui::TextWrapped("You can continue the scan for all other accessible processes.");
        ImGui::Dummy(ImVec2(0, 10));
        if (ImGui::Button("Continue Anyway", ImVec2(140, 0))) {
            ImGui::CloseCurrentPopup();
        }
        ImGui::SameLine();
        if (AccentButton(ICON_FA_SHIELD_ALT " Elevate & Restart", state, ImVec2(180, 0))) {
            state.elevation_requested = true;
            ImGui::CloseCurrentPopup();
        }
        ImGui::EndPopup();
    }
}