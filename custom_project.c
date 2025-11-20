// system_custom_project.c
// Compile:
//   cl system_custom_project.c /link user32.lib advapi32.lib wininet.lib
// or:
//   gcc system_custom_project.c -o project.exe -luser32 -ladvapi32 -lwininet

#include <windows.h>
#include <shlobj.h>
#include <wininet.h>
#include <stdio.h>

#pragma comment(lib, "wininet.lib")

// ---------------------------------------------------
// Utility: Show last Windows error
// ---------------------------------------------------
void PrintLastError(const char *msg) {
    DWORD e = GetLastError();
    LPVOID p;
    FormatMessageA(FORMAT_MESSAGE_ALLOCATE_BUFFER | FORMAT_MESSAGE_FROM_SYSTEM,
                   NULL, e, 0, (LPSTR)&p, 0, NULL);
    fprintf(stderr, "%s: %s\n", msg, (char *)p);
    LocalFree(p);
}

// ---------------------------------------------------
// Download file (used for wallpaper)
// ---------------------------------------------------
int DownloadFile(const char *url, const char *out) {
    HINTERNET hI = InternetOpenA("Downloader", INTERNET_OPEN_TYPE_DIRECT, NULL, NULL, 0);
    if (!hI) { PrintLastError("InternetOpen"); return 0; }

    HINTERNET hF = InternetOpenUrlA(hI, url, NULL, 0, INTERNET_FLAG_RELOAD, 0);
    if (!hF) { PrintLastError("InternetOpenUrl"); InternetCloseHandle(hI); return 0; }

    FILE *fp = fopen(out, "wb");
    if (!fp) { printf("Cannot create file.\n"); return 0; }

    char buf[4096];
    DWORD read;
    while (InternetReadFile(hF, buf, sizeof(buf), &read) && read)
        fwrite(buf, 1, read, fp);

    fclose(fp);
    InternetCloseHandle(hF);
    InternetCloseHandle(hI);

    return 1;
}

// ---------------------------------------------------
// Change wallpaper
// ---------------------------------------------------
int SetWallpaperFromFile(const char *file) {
    return SystemParametersInfoA(SPI_SETDESKWALLPAPER, 0, (PVOID)file,
                                 SPIF_UPDATEINIFILE | SPIF_SENDCHANGE);
}

// ---------------------------------------------------
// Registry modification example
// ---------------------------------------------------
#include <windows.h>
#include <stdio.h>

void ModifyRegistry() {
    HKEY hKey;


    const char* stringValue = "Hello Registry";   // REG_SZ
    DWORD dwordValue1 = 111;                      // REG_DWORD
    DWORD dwordValue2 = 222;                      // REG_DWORD
    BYTE binaryValue[5] = {1, 2, 3, 4, 5};       // REG_BINARY

    if (RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\SampleProject",
                        0, NULL, 0, KEY_ALL_ACCESS, NULL, &hKey, NULL) == ERROR_SUCCESS) {

        RegSetValueExA(hKey, "StringValue", 0, REG_SZ, (BYTE*)stringValue, (DWORD)(strlen(stringValue) + 1));
        printf("[Registry] Created StringValue = %s\n", stringValue);

        RegSetValueExA(hKey, "DwordValue1", 0, REG_DWORD, (BYTE*)&dwordValue1, sizeof(dwordValue1));
        printf("[Registry] Created DwordValue1 = %d\n", dwordValue1);

        RegSetValueExA(hKey, "DwordValue2", 0, REG_DWORD, (BYTE*)&dwordValue2, sizeof(dwordValue2));
        printf("[Registry] Created DwordValue2 = %d\n", dwordValue2);

        RegSetValueExA(hKey, "BinaryValue", 0, REG_BINARY, binaryValue, sizeof(binaryValue));
        printf("[Registry] Created BinaryValue = {1,2,3,4,5}\n");

        RegCloseKey(hKey);
    } else {
        printf("[Registry] Failed to create or open key.\n");
    }
}
void DeleteRegistryValues() {
    HKEY hKey;

    if (RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\SampleProject", 0, KEY_ALL_ACCESS, &hKey) == ERROR_SUCCESS) {
        const char* valuesToDelete[] = {"DwordValue2", "BinaryValue"};
        for (int i = 0; i < 2; i++) {
            if (RegDeleteValueA(hKey, valuesToDelete[i]) == ERROR_SUCCESS)
                printf("[Registry] Deleted %s\n", valuesToDelete[i]);
            else
                printf("[Registry] Failed to delete %s\n", valuesToDelete[i]);
        }

        RegCloseKey(hKey);
    } else {
        printf("[Registry] Failed to open key for deletion.\n");
    }
}

// ---------------------------------------------------
// Create directories + files
// ---------------------------------------------------
void CreateFiles() {
    CreateDirectoryA("C:\\SampleProjectDir1", NULL);
    CreateDirectoryA("C:\\SampleProjectDir2", NULL);

    // Create text file in Folder 1 (KEPT)
    FILE *f1 = fopen("C:\\SampleProjectDir1\\message.txt", "w");
    if (f1) {
        fprintf(f1, "Hello, This is a sample project\n");
        fclose(f1);
    }

    // Create binary file in Folder 2 (DELETED LATER)
    FILE *f2 = fopen("C:\\SampleProjectDir2\\data.dat", "wb");
    if (f2) {
        unsigned char data[] = {0xDE, 0xAD, 0xBE, 0xEF, '@', '#', '$'};
        fwrite(data, sizeof(data), 1, f2);
        fclose(f2);
    }

    printf("[Files] Created directories and files.\n");
}

void DeleteFiles() {
    // Delete ONLY Folder 2
    DeleteFileA("C:\\SampleProjectDir2\\data.dat");
    RemoveDirectoryA("C:\\SampleProjectDir2");

    printf("[Files] Deleted Dir2 and its file. Dir1 kept.\n");
}



// ---------------------------------------------------
// Launch CMD and open Paint from it
// ---------------------------------------------------
void LaunchCmdThenPaint() {
    STARTUPINFOA si = {0};
    PROCESS_INFORMATION pi = {0};
    si.cb = sizeof(si);

    // Launch CMD
    if (!CreateProcessA("C:\\Windows\\System32\\cmd.exe", NULL, NULL, NULL,
                        FALSE, 0, NULL, NULL, &si, &pi)) {
        PrintLastError("CreateProcess CMD");
        return;
    }

    Sleep(500); // give CMD time to open

    // Launch paint.exe FROM cmd using system()
    system("start mspaint.exe");


    printf("[Process] CMD and Paint launched.\n");
}

// ---------------------------------------------------
// MAIN PROGRAM
// ---------------------------------------------------
int main() {
    // Safety
    if (MessageBoxA(NULL,
        "This project will create & delete local files/directories,\n"
        "modify Windows registry keys,\n"
        "change wallpaper,\n"
        "and launch CMD + Paint.\n\n"
        "Do you want to continue?",
        "Safety Confirmation",
        MB_YESNO | MB_ICONWARNING) != IDYES) {

        printf("User cancelled.\n");
        return 0;
    }

    // 1. Create files
    CreateFiles();

    // 2. Modify registry
    ModifyRegistry();

    //
    printf("\nNow deleting some values...\n\n");
    DeleteRegistryValues();

    // 3. Download wallpaper
    const char *url = "https://mcdn.wallpapersafari.com/medium/22/13/OPiBcm.jpg"; // <<< Replace this
    char wall[MAX_PATH];
    GetTempPathA(MAX_PATH, wall);
    strcat(wall, "wallpaper.jpg");


    printf("[Wallpaper] Downloading...\n");
    if (DownloadFile(url, wall)) {
        printf("[Wallpaper] Setting wallpaper.\n");
        SetWallpaperFromFile(wall);
    } else {
        printf("[Wallpaper] Download failed.\n");
    }

    // 4. Open CMD and Paint
    LaunchCmdThenPaint();

    // 5. Cleanup files
    DeleteFiles();

    MessageBoxA(NULL, "All operations complete.", "Done", MB_OK);
    return 0;
}
