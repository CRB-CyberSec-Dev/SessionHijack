#include <iostream>
#include <fstream>
#include <string>
#include <boost/asio.hpp>
#include <jwt-cpp/jwt.h>
#include <iomanip>

#define _CRT_SECURE_NO_WARNINGS

//Set the token payload name and password here
#define tname  "crb"
#define tpass  "crb1234"

using boost::asio::ip::tcp;
using namespace std;

string LoadKey(const string& file_path) {
    ifstream key_file(file_path);
    if (!key_file.is_open()) {
        throw runtime_error("Could not open key file");
    }
    stringstream key_stream;
    key_stream << key_file.rdbuf();
    return key_stream.str();
}




bool ReceiveFileOverSocket(tcp::socket& socket, const string& file_path) {

    // Receive the JWT token
    boost::asio::streambuf response;
    boost::system::error_code error;


    istream response_stream(&response);


    // Receive the file size
    size_t file_size;
    boost::asio::read(socket, boost::asio::buffer(&file_size, sizeof(file_size)), error);

    if (error) {
        cerr << "Failed to read file size: " << error.message() << endl;
        return false;
    }

    // Receive the file content
    vector<char> buffer(file_size);
    boost::asio::read(socket, boost::asio::buffer(buffer), error);

    if (error && error != boost::asio::error::eof) {
        cerr << "Failed to read file content: " << error.message() << endl;
        return false;
    }

    // Write the received content to a file
    ofstream file(file_path, ios::binary);
    if (!file.is_open()) {
        cerr << "Failed to open file: " << file_path << endl;
        return false;
    }

    file.write(buffer.data(), file_size);

    cout << "File received and saved successfully!" << endl;
    return true;
}

//JWT token genarate
string GenerateToken(const string& private_key, const string& issuer, const string& subject, int expiration_seconds) {



    cout << private_key << endl;

    auto token = jwt::create()
        .set_issuer(issuer)
        .set_subject(subject)
        .set_issued_at(std::chrono::system_clock::now())
        .set_expires_at(std::chrono::system_clock::now() + std::chrono::seconds{ expiration_seconds }) // Expires in 1 hour
        .set_payload_claim("name", jwt::claim(std::string{ tname }))
        .set_payload_claim("pass", jwt::claim(std::string{ tpass }))
        .sign(jwt::algorithm::rs256("", private_key, "", ""));

    return token;

}



// function to parse a date or time string.
chrono::system_clock::time_point GFG(const string& datetimeString, const string& format)
{
    tm tmStruct = {};
    istringstream ss(datetimeString);
    ss >> get_time(&tmStruct, format.c_str());
    return chrono::system_clock::from_time_t(
        mktime(&tmStruct));
}

// Function to format a time_t value into a date or time string.
std::string DateTime(const std::chrono::system_clock::time_point& timePoint, const std::string& format)
{
    // Convert time_point to time_t
    std::time_t time = std::chrono::system_clock::to_time_t(timePoint);

    // Use localtime_s instead of localtime for safety
    struct tm timeinfo;
    if (localtime_s(&timeinfo, &time) != 0) {
        throw std::runtime_error("Failed to convert time_point to tm structure.");
    }

    // Format the time using strftime
    char buffer[70];
    if (strftime(buffer, sizeof(buffer), format.c_str(), &timeinfo) == 0) {
        throw std::runtime_error("Failed to format time.");
    }

    // Convert formatted time to std::string and remove spaces
    std::string formattedTime(buffer);
    formattedTime.erase(std::remove_if(formattedTime.begin(), formattedTime.end(), [](unsigned char c) { return std::isspace(c) || c == ':'; }), formattedTime.end());

    return formattedTime;
}


int main() {
    try {
        boost::asio::io_context io_context;
        tcp::acceptor acceptor(io_context, tcp::endpoint(tcp::v4(), 8080));

        cout << "Server is running. Waiting for a connection..." << endl;

        for (;;) {
            tcp::socket socket(io_context);
            acceptor.accept(socket);

            cout << "Client connected!" << endl;


            string private_key = LoadKey("private_key.pem");
            //String to wstring
            wstring wsprivate_key(private_key.begin(), private_key.end());

            //MessageBox(NULL, wsprivate_key.c_str(), L"Error", MB_OK | MB_ICONERROR);


            string issuer = "your-app";
            string subject = "user@example.com";
            int expiration_seconds = 3600; // 1 hour

            string token = GenerateToken(private_key, issuer, subject, expiration_seconds);

            cout << "Generated JWT token: " << token << endl;

            boost::system::error_code ignored_error;
            boost::asio::write(socket, boost::asio::buffer(token + "\n"), ignored_error);



            // Receive the JWT subject for veryfication
            boost::asio::streambuf response;
            boost::system::error_code error;

            boost::asio::read_until(socket, response, '\n', error);
            istream response_stream(&response);
            string name, pass;
            getline(response_stream, name);
            getline(response_stream, pass);


            if (!(name == tname && pass == tpass)) {
                cout << "Invalid user name and password in JWT " << endl;
                socket.close();
            }
            else {

                cout << "Validated successefull. user name and password in JWT is" + name + " " + pass << endl;

                const string datetimeString = "2023-05-22 12:24:52";
                const string format = "%Y-%m-%d %H:%M:%S";

                chrono::system_clock::time_point parsedTime = GFG(datetimeString, format);
                string formattedTime = DateTime(parsedTime, format);
                string file_path = formattedTime + "_cookies.tar";

                if (!ReceiveFileOverSocket(socket, file_path)) {
                    cerr << "Failed to receive the file." << endl;
                }
                else {
                    cout << "File recieved success. " << file_path << endl;
                };

                socket.close();


            };



            cout << "Waiting for a new connection..." << endl;


        }
    }
    catch (exception& e) {
        cerr << "Exception: " << e.what() << endl;
    }

    return 0;
}
