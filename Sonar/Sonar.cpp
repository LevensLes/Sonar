#include "imgui.h"
#include "imgui_impl_glfw.h"
#include "imgui_impl_opengl3.h"
#include <GLFW/glfw3.h>
#include <string>
#include <windows.h>
#include <shellapi.h> // Required for ShellExecuteExA

#include "ui.h"
#include "backend.h"
#include "icons.h"

void ElevateAndRestart() {
    char path[MAX_PATH];
    GetModuleFileNameA(NULL, path, MAX_PATH);
    SHELLEXECUTEINFOA sei = { sizeof(sei) };
    sei.lpVerb = "runas";
    sei.lpFile = path;
    sei.hwnd = NULL;
    sei.nShow = SW_NORMAL;
    ShellExecuteExA(&sei);
}


bool EnableDebugPrivilege() {
    HANDLE hToken;
    if (!OpenProcessToken(GetCurrentProcess(), TOKEN_ADJUST_PRIVILEGES | TOKEN_QUERY, &hToken)) return false;
    TOKEN_PRIVILEGES tp;
    LUID luid;
    if (!LookupPrivilegeValue(NULL, SE_DEBUG_NAME, &luid)) { CloseHandle(hToken); return false; }
    tp.PrivilegeCount = 1;
    tp.Privileges[0].Luid = luid;
    tp.Privileges[0].Attributes = SE_PRIVILEGE_ENABLED;
    if (!AdjustTokenPrivileges(hToken, FALSE, &tp, sizeof(TOKEN_PRIVILEGES), (PTOKEN_PRIVILEGES)NULL, (PDWORD)NULL)) { CloseHandle(hToken); return false; }
    if (GetLastError() == ERROR_NOT_ALL_ASSIGNED) { CloseHandle(hToken); return false; }
    CloseHandle(hToken);
    return true;
}

void DropCallback(GLFWwindow* window, int count, const char** paths) {
    AppState* state = static_cast<AppState*>(glfwGetWindowUserPointer(window));
    if (state && count > 0) {
        std::lock_guard<std::mutex> lock(state->drop_mutex);
        state->path_to_drop = paths[0];
    }
}


// sonar.cpp (Corrected)

// sonar.cpp (Corrected for Typo)

int main(int, char**)
{
    // 1. Setup GLFW and create a FRAMELESS window
    if (!glfwInit()) return 1;
    glfwWindowHint(GLFW_CONTEXT_VERSION_MAJOR, 3);
    glfwWindowHint(GLFW_CONTEXT_VERSION_MINOR, 3);
    glfwWindowHint(GLFW_OPENGL_PROFILE, GLFW_OPENGL_CORE_PROFILE);
    glfwWindowHint(GLFW_DECORATED, GLFW_FALSE);

    const int window_width = 1480;
    const int window_height = 820;
    GLFWwindow* window = glfwCreateWindow(window_width, window_height, "Sonar Toolkit", NULL, NULL);
    if (window == NULL) { glfwTerminate(); return 1; }

    const GLFWvidmode* vidmode = glfwGetVideoMode(glfwGetPrimaryMonitor());
    if (vidmode) {
        int x = (vidmode->width - window_width) / 2;
        int y = (vidmode->height - window_height) / 2;
        glfwSetWindowPos(window, x, y);
    }

    glfwMakeContextCurrent(window);
    glfwSwapInterval(1);

    // 2. Setup Dear ImGui
    IMGUI_CHECKVERSION();
    ImGui::CreateContext();
    ImGuiIO& io = ImGui::GetIO(); (void)io;
    io.ConfigFlags |= ImGuiConfigFlags_NavEnableKeyboard;
    io.ConfigFlags |= ImGuiConfigFlags_DockingEnable;
    io.ConfigFlags |= ImGuiConfigFlags_ViewportsEnable;

    // When viewports are enabled, tweak WindowRounding/WindowBg so platform windows can look identical to regular ones.
    ImGuiStyle& style = ImGui::GetStyle();
    if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
    {
        style.WindowRounding = 0.0f;
        style.Colors[ImGuiCol_WindowBg].w = 1.0f;
    }

    float title_font_size = 18.0f;

    io.Fonts->AddFontFromFileTTF("Inter-Regular.ttf", title_font_size);

    static const ImWchar icons_ranges[] = { ICON_MIN_FA, ICON_MAX_FA, 0 };
    ImFontConfig icons_config;
    icons_config.MergeMode = true;
    icons_config.PixelSnapH = true;

    io.Fonts->AddFontFromFileTTF(FONT_ICON_FILE_NAME_FAS, title_font_size, &icons_config, icons_ranges);

    io.Fonts->Build();

    ImGui_ImplGlfw_InitForOpenGL(window, true);
    ImGui_ImplOpenGL3_Init("#version 130");

    // 3. Initialize application state and load settings
    AppState state;
    //InitializeAppState(state); // Assuming this function exists in backend.h
    LoadSettings(state);

    // 4. Apply custom style using loaded settings
    ApplySonarStyle(state);

    // 5. Initialize runtime state
    state.has_debug_privilege = EnableDebugPrivilege();
    state.process_list = GetProcessList();
    state.quick_scan_selections.resize(state.process_list.size(), false);

    PushLog(state.quick_scan_lines, state.accent_color, ICON_FA_INFO_CIRCLE " Sonar initialized. Found %zu processes.", state.process_list.size());
    if (state.has_debug_privilege) {
        PushLog(state.forensic_log_lines, ImVec4(0.7f, 0.95f, 0.7f, 1.0f), ICON_FA_CHECK_CIRCLE " SeDebugPrivilege enabled. Full process access granted.");
    }
    else {
        PushLog(state.forensic_log_lines, ImVec4(0.98f, 0.82f, 0.45f, 1.0f), ICON_FA_WARNING " Failed to enable SeDebugPrivilege. Run as Administrator for full access.");
        state.show_admin_toast = true;
    }

    glfwSetWindowUserPointer(window, &state);
    glfwSetDropCallback(window, DropCallback);

    // 6. Main loop
    while (!glfwWindowShouldClose(window))
    {
        if (state.elevation_requested) {
            ElevateAndRestart();
            glfwSetWindowShouldClose(window, true); // Close the current instance
        }

        glfwPollEvents();

        ImGui_ImplOpenGL3_NewFrame();
        ImGui_ImplGlfw_NewFrame();
        ImGui::NewFrame();

        RenderUI(state, window);

        ImGui::Render();
        int display_w, display_h;
        glfwGetFramebufferSize(window, &display_w, &display_h);
        glViewport(0, 0, display_w, display_h);

        // --- THIS IS THE CORRECTED LINE ---
        ImVec4 clear_color = ImGui::GetStyle().Colors[ImGuiCol_WindowBg];
        glClearColor(clear_color.x, clear_color.y, clear_color.z, clear_color.w);
        glClear(GL_COLOR_BUFFER_BIT);
        ImGui_ImplOpenGL3_RenderDrawData(ImGui::GetDrawData());

        if (io.ConfigFlags & ImGuiConfigFlags_ViewportsEnable)
        {
            GLFWwindow* backup_current_context = glfwGetCurrentContext();
            ImGui::UpdatePlatformWindows();
            ImGui::RenderPlatformWindowsDefault();
            glfwMakeContextCurrent(backup_current_context);
        }

        glfwSwapBuffers(window);
    }

    // 7. Cleanup
    ImGui_ImplOpenGL3_Shutdown();
    ImGui_ImplGlfw_Shutdown();
    ImGui::DestroyContext();
    glfwDestroyWindow(window);
    glfwTerminate();

    return 0;
}